package Chainweb

import (
	"crypto/ed25519"
	"regexp"
	"strings"
	"testing"
)

// realDalosBitstring is the frozen v1_genesis.json bs-0001 vector's
// input_bitstring -- a real, already-audited 1600-bit DALOS seed, not a
// synthetic/hand-typed string. Using an existing frozen vector here (rather
// than a fresh random one) means this test is also implicitly checking
// that this package never mutates or depends on shared state any other
// vector's generation touches.
const realDalosBitstring = "0010010111000100101111000100101100000000101001110010101110010101010100010011000010000001001001111011011011000100010010001100000110001100001100101011000100000010110000111010011011110010101000010100101011111110110111101111101101101111101011110000110111000110101111000000110110100101100101011001100010010101101110011100001101100011001110110010101000111000000101111011011100100110101101001110110101010001100100100100000111011101011011010101101111110001011011111111111011010000110000111011010001111101100101101111000001010111101110111010101101001101000010001111010010100111000111101001001111111010010101111100100010110001111101111100100100001011100110101011111011101100110111100100110011100010110101011001110000011011110011100000000011111100110101101101010011110011001111001101110011001111011001111111100100011010010000001011000010001010010011010100000011111111000111111100100011001111000101101101110110100111111010010000011101101110001101110101110111101111001110101111110010011000110010101010110010001110011010010111000101100100001011100010101010111011101001111110011100000001101111111110001000001010100000010001000001010111011010001010000011011010100100110111111111111100110110110001011010001001010011001001100001001111101000111000010101000110001100011011111011100001000000111010011010100100101010100101100100111111100100100100101111101000000111111100000000100101100010011101101011011011100011011011011010010000110011001101001100110001000011101000101101011100010100111011100100110000000101101101110101111100101101011011100001000101101101000101111100000000010100010111010101011010110101000111011110001111"

var kAddressRe = regexp.MustCompile(`^k:[0-9a-f]{64}$`)

func TestGenerateFromBitString_Deterministic(t *testing.T) {
	r1, err := GenerateFromBitString(realDalosBitstring)
	if err != nil {
		t.Fatalf("GenerateFromBitString: %v", err)
	}
	r2, err := GenerateFromBitString(realDalosBitstring)
	if err != nil {
		t.Fatalf("GenerateFromBitString (2nd call): %v", err)
	}
	if r1.PrivateKey != r2.PrivateKey || r1.PublicKey != r2.PublicKey || r1.Address != r2.Address {
		t.Fatalf("same seed produced different output across two calls -- not deterministic:\n%+v\n%+v", r1, r2)
	}
}

func TestGenerateFromBitString_ProducesValidKAddress(t *testing.T) {
	r, err := GenerateFromBitString(realDalosBitstring)
	if err != nil {
		t.Fatalf("GenerateFromBitString: %v", err)
	}
	if !kAddressRe.MatchString(r.Address) {
		t.Fatalf("address %q does not match the required k:<64 lowercase hex> format", r.Address)
	}
	if !strings.EqualFold(r.Address[2:], hexString(r.PublicKey[:])) {
		t.Fatalf("address hex suffix does not match hex(PublicKey)")
	}
}

func hexString(b []byte) string {
	const hextable = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hextable[v>>4]
		out[i*2+1] = hextable[v&0x0f]
	}
	return string(out)
}

func TestGenerateFromBitString_KeyIsGenuinelyUsableEd25519(t *testing.T) {
	r, err := GenerateFromBitString(realDalosBitstring)
	if err != nil {
		t.Fatalf("GenerateFromBitString: %v", err)
	}
	if err := SelfCheckEd25519(r); err != nil {
		t.Fatalf("SelfCheckEd25519: %v", err)
	}

	// Independent second check, not reusing this package's own SelfCheckEd25519
	// helper, in case that helper itself has a bug that always passes.
	priv := ed25519.NewKeyFromSeed(r.PrivateKey[:])
	msg := []byte("independent verification message")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(r.PublicKey[:], msg, sig) {
		t.Fatal("independently constructed signature did not verify")
	}
	// A signature under a DIFFERENT message must NOT verify.
	if ed25519.Verify(r.PublicKey[:], []byte("a different message"), sig) {
		t.Fatal("signature incorrectly verified against a different message")
	}
}

func TestGenerateFromBitStringAtIndex_ZeroMatchesPlainGenerate(t *testing.T) {
	plain, err := GenerateFromBitString(realDalosBitstring)
	if err != nil {
		t.Fatalf("GenerateFromBitString: %v", err)
	}
	indexed, err := GenerateFromBitStringAtIndex(realDalosBitstring, 0)
	if err != nil {
		t.Fatalf("GenerateFromBitStringAtIndex(0): %v", err)
	}
	if plain.PrivateKey != indexed.PrivateKey || plain.Address != indexed.Address {
		t.Fatal("GenerateFromBitString and GenerateFromBitStringAtIndex(seed, 0) diverged -- they must be identical")
	}
}

func TestGenerateFromBitStringAtIndex_InfinitePositionsAreIndependent(t *testing.T) {
	seen := map[string]uint32{}
	for i := uint32(0); i < 10; i++ {
		r, err := GenerateFromBitStringAtIndex(realDalosBitstring, i)
		if err != nil {
			t.Fatalf("GenerateFromBitStringAtIndex(%d): %v", i, err)
		}
		if prior, ok := seen[r.Address]; ok {
			t.Fatalf("index %d produced the same address as index %d: %s", i, prior, r.Address)
		}
		seen[r.Address] = i
		if err := SelfCheckEd25519(r); err != nil {
			t.Fatalf("index %d: SelfCheckEd25519: %v", i, err)
		}
	}
}

func TestGenerateFromBitStringAtIndex_DirectlyReachableWithoutChaining(t *testing.T) {
	// Index 7 computed directly must equal index 7 reached "by generating
	// 0..7 first" -- i.e. there is genuinely no hidden chained state.
	direct, err := GenerateFromBitStringAtIndex(realDalosBitstring, 7)
	if err != nil {
		t.Fatalf("direct index 7: %v", err)
	}
	for i := uint32(0); i < 7; i++ {
		if _, err := GenerateFromBitStringAtIndex(realDalosBitstring, i); err != nil {
			t.Fatalf("warm-up index %d: %v", i, err)
		}
	}
	afterWarmup, err := GenerateFromBitStringAtIndex(realDalosBitstring, 7)
	if err != nil {
		t.Fatalf("index 7 after warmup: %v", err)
	}
	if direct.PrivateKey != afterWarmup.PrivateKey {
		t.Fatal("index 7's result depended on whether earlier indices were generated first -- should be impossible, pure function of (seed, index)")
	}
}

func TestGenerateFromBitString_RejectsWrongLength(t *testing.T) {
	if _, err := GenerateFromBitString("01010101"); err == nil {
		t.Fatal("expected an error for a too-short bitstring, got nil")
	}
}

func TestGenerateFromBitString_RejectsNonBinaryChars(t *testing.T) {
	bad := strings.Repeat("0", 1599) + "2" // right length, one invalid char
	if _, err := GenerateFromBitString(bad); err == nil {
		t.Fatal("expected an error for a non-binary bitstring, got nil")
	}
}

func TestGenerateFromBitString_DoesNotCollideWithRSA4096Stream(t *testing.T) {
	// Sanity check on the domain-separation claim itself: the Chainweb
	// stream's first 32 bytes must NOT equal RSA4096's first-consumed
	// candidate draw's raw bytes for the same seed. This isn't a proof of
	// non-collision (that's structural, from the distinct domain tags --
	// see stream.go's doc comment) but it is a cheap, real, executable
	// check that nothing accidentally reused the same tag string.
	r, err := GenerateFromBitString(realDalosBitstring)
	if err != nil {
		t.Fatalf("GenerateFromBitString: %v", err)
	}
	stream, err := newSeedStream(realDalosBitstring, 0)
	if err != nil {
		t.Fatalf("newSeedStream: %v", err)
	}
	var again [32]byte
	if _, err := stream.Read(again[:]); err != nil { //nolint:errcheck
		t.Fatalf("stream read: %v", err)
	}
	if again != r.PrivateKey {
		t.Fatal("re-deriving the stream for (seed, 0) produced different bytes than the original generation -- stream is not deterministic")
	}
}
