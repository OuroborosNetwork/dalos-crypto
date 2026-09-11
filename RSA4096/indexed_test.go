package RSA4096

import (
	"strings"
	"testing"
)

// --- deriveIndexedSeedBitString: cheap, no prime search ------------------

func TestDeriveIndexedSeedBitString_SameLengthAsInput(t *testing.T) {
	for _, length := range []int{apolloTestSeedLen, dalosTestSeedLen} {
		seed := fixedTestSeedOfLength(length)
		derived, err := deriveIndexedSeedBitString(seed, 1)
		if err != nil {
			t.Fatalf("length %d: unexpected error: %v", length, err)
		}
		if len(derived) != length {
			t.Fatalf("length %d: derived seed has length %d, want %d", length, len(derived), length)
		}
		for _, c := range derived {
			if c != '0' && c != '1' {
				t.Fatalf("length %d: derived seed contains non-binary character %q", length, c)
			}
		}
	}
}

func TestDeriveIndexedSeedBitString_Deterministic(t *testing.T) {
	seed := fixedTestSeed()
	a, err := deriveIndexedSeedBitString(seed, 42)
	if err != nil {
		t.Fatal(err)
	}
	b, err := deriveIndexedSeedBitString(seed, 42)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("same (seed, index) produced two different derived seeds")
	}
}

func TestDeriveIndexedSeedBitString_DifferentIndicesDiverge(t *testing.T) {
	seed := fixedTestSeed()
	seen := make(map[string]uint32)
	for _, idx := range []uint32{1, 2, 3, 1000000, 4294967295} {
		derived, err := deriveIndexedSeedBitString(seed, idx)
		if err != nil {
			t.Fatalf("index %d: unexpected error: %v", idx, err)
		}
		if prior, exists := seen[derived]; exists {
			t.Fatalf("index %d produced the same derived seed as index %d", idx, prior)
		}
		seen[derived] = idx
	}
}

func TestDeriveIndexedSeedBitString_DifferentSeedsDiverge(t *testing.T) {
	seedA := fixedTestSeed()
	seedB := "0" + seedA[1:]
	if seedA[0] == '0' {
		seedB = "1" + seedA[1:]
	}
	a, err := deriveIndexedSeedBitString(seedA, 7)
	if err != nil {
		t.Fatal(err)
	}
	b, err := deriveIndexedSeedBitString(seedB, 7)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("flipping one bit of the parent seed did not change the index-7 derived seed")
	}
}

func TestDeriveIndexedSeedBitString_RejectsInvalidSeed(t *testing.T) {
	if _, err := deriveIndexedSeedBitString(strings.Repeat("0", 1300), 1); err == nil {
		t.Fatal("expected an error for a seed length outside {1024, 1600}, got nil")
	}
}

// hashBytesToBitString: pure rendering, no dependencies worth mocking.
func TestHashBytesToBitString_KnownValues(t *testing.T) {
	got := hashBytesToBitString([]byte{0x00, 0xFF, 0xA5})
	want := "000000001111111110100101"
	if got != want {
		t.Fatalf("hashBytesToBitString([0x00, 0xFF, 0xA5]) = %q, want %q", got, want)
	}
}

// --- GenerateFromBitStringAtIndex: a few real, end-to-end runs -----------

// TestGenerateFromBitStringAtIndex_IndexZeroMatchesUnindexedCall is the
// core backward-compatibility guarantee: address #0 via the new indexed
// API must be BYTE-IDENTICAL to calling GenerateFromBitString directly,
// forever -- this is what keeps every already-published, already-frozen
// result (testvectors/v2_rsa4096.json, the live npm package) valid.
func TestGenerateFromBitStringAtIndex_IndexZeroMatchesUnindexedCall(t *testing.T) {
	seed := fixedTestSeed()

	direct, err := GenerateFromBitString(seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	indexed, err := GenerateFromBitStringAtIndex(seed, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	if direct.Key.N.Cmp(indexed.Key.N) != 0 {
		t.Fatal("GenerateFromBitStringAtIndex(seed, 0, ...) produced a different modulus than GenerateFromBitString(seed, ...)")
	}
	if direct.Address != indexed.Address {
		t.Fatalf("index 0 address %q != unindexed address %q", indexed.Address, direct.Address)
	}
	if direct.PAttempts != indexed.PAttempts || direct.QAttempts != indexed.QAttempts {
		t.Fatal("index 0 attempt counts differ from the unindexed call -- the seed stream itself changed")
	}
}

// TestGenerateFromBitStringAtIndex_NonZeroIndexProducesAnIndependentAddress
// confirms index 1 produces a real, valid, DIFFERENT key from index 0 --
// the actual feature this file exists to add.
func TestGenerateFromBitStringAtIndex_NonZeroIndexProducesAnIndependentAddress(t *testing.T) {
	seed := fixedTestSeed()

	addr0, err := GenerateFromBitStringAtIndex(seed, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr1, err := GenerateFromBitStringAtIndex(seed, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	if addr0.Address == addr1.Address {
		t.Fatal("index 0 and index 1 produced the SAME Arweave address from the same seed")
	}
	if addr0.Key.N.Cmp(addr1.Key.N) == 0 {
		t.Fatal("index 0 and index 1 produced the SAME RSA modulus from the same seed")
	}
	if err := SelfCheckTextbookRSA(addr1.Key); err != nil {
		t.Fatalf("index 1's key failed the textbook RSA self-check: %v", err)
	}
}

// TestGenerateFromBitStringAtIndex_DirectRandomAccess confirms an index
// can be generated directly without ever having generated the indices
// before it -- no sequential/consecutive dependency, matching the
// explicit requirement that any index be reachable on demand.
func TestGenerateFromBitStringAtIndex_DirectRandomAccess(t *testing.T) {
	seed := fixedTestSeed()

	// Jump straight to a high, "unwalked" index.
	direct, err := GenerateFromBitStringAtIndex(seed, 777, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Recompute it again, independently, with no shared state --
	// confirms it really is a pure function of (seed, index), not
	// something that accumulates state from having been "visited"
	// before.
	again, err := GenerateFromBitStringAtIndex(seed, 777, nil)
	if err != nil {
		t.Fatal(err)
	}

	if direct.Address != again.Address {
		t.Fatal("index 777 produced different addresses across two independent calls")
	}
}
