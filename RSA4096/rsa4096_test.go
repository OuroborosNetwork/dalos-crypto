package RSA4096

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// fixedTestSeed is a deterministic, fixed-shape 1600-bit seed used across
// this file's tests. NOT a real DALOS-derived seed (that would require the
// full seed-word/Elliptic pipeline) -- just a fixed pattern repeated to the
// required length, so every test run exercises exactly the same input.
func fixedTestSeed() string {
	var sb strings.Builder
	pattern := "1101001011010110"
	for sb.Len() < seedBitStringLen {
		sb.WriteString(pattern)
	}
	return sb.String()[:seedBitStringLen]
}

// --- stream.go ---------------------------------------------------------

func TestNewSeedStream_Deterministic(t *testing.T) {
	seed := fixedTestSeed()

	r1, err := NewSeedStream(seed)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := NewSeedStream(seed)
	if err != nil {
		t.Fatal(err)
	}

	buf1 := make([]byte, 4096)
	buf2 := make([]byte, 4096)
	if _, err := r1.Read(buf1); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Read(buf2); err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(buf1) != hex.EncodeToString(buf2) {
		t.Fatal("two independent streams from the same seed produced different bytes")
	}
}

func TestNewSeedStream_DifferentSeedsDiverge(t *testing.T) {
	seed := fixedTestSeed()
	flipped := "0" + seed[1:]
	if seed[0] == '0' {
		flipped = "1" + seed[1:]
	}

	r1, err := NewSeedStream(seed)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := NewSeedStream(flipped)
	if err != nil {
		t.Fatal(err)
	}

	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)
	if _, err := r1.Read(buf1); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Read(buf2); err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(buf1) == hex.EncodeToString(buf2) {
		t.Fatal("flipping one seed bit did not change the stream output")
	}
}

func TestNewSeedStream_RejectsInvalidSeed(t *testing.T) {
	cases := map[string]string{
		"too short":       strings.Repeat("0", seedBitStringLen-1),
		"too long":        strings.Repeat("0", seedBitStringLen+1),
		"non-binary char": strings.Repeat("2", seedBitStringLen),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSeedStream(bad); err == nil {
				t.Fatalf("expected an error for %s, got nil", name)
			}
		})
	}
}

// --- candidate.go --------------------------------------------------------

func TestGenerateCandidate_BitFixingInvariants(t *testing.T) {
	stream, err := NewSeedStream(fixedTestSeed())
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		c, err := GenerateCandidate(stream)
		if err != nil {
			t.Fatal(err)
		}
		if c.BitLen() != candidateBits {
			t.Errorf("candidate %d: bit length = %d, want %d", i, c.BitLen(), candidateBits)
		}
		if c.Bit(0) != 1 {
			t.Errorf("candidate %d: not odd", i)
		}
		if c.Bit(candidateBits-1) != 1 || c.Bit(candidateBits-2) != 1 {
			t.Errorf("candidate %d: top two bits not both set", i)
		}
	}
}

func TestGenerateCandidate_Deterministic(t *testing.T) {
	seed := fixedTestSeed()

	s1, err := NewSeedStream(seed)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSeedStream(seed)
	if err != nil {
		t.Fatal(err)
	}

	c1, err := GenerateCandidate(s1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := GenerateCandidate(s2)
	if err != nil {
		t.Fatal(err)
	}

	if c1.Cmp(c2) != 0 {
		t.Fatal("same seed produced different first candidates across two fresh streams")
	}
}

// --- primes.go -------------------------------------------------------------

func TestSmallOddPrimes_ActuallyPrime(t *testing.T) {
	primes := smallOddPrimesCache
	if len(primes) != SmallPrimeCount {
		t.Fatalf("got %d small primes, want %d", len(primes), SmallPrimeCount)
	}
	if primes[0] != 3 || primes[1] != 5 || primes[2] != 7 || primes[3] != 11 {
		t.Fatalf("first few small primes wrong: %v", primes[:4])
	}
	// Spot-check every entry is actually prime and odd, and the list is
	// strictly increasing (no duplicates, no skipped-then-repeated bugs).
	for i, p := range primes {
		if p%2 == 0 {
			t.Fatalf("index %d: %d is even", i, p)
		}
		if !new(big.Int).SetUint64(p).ProbablyPrime(20) {
			t.Fatalf("index %d: %d is not prime", i, p)
		}
		if i > 0 && p <= primes[i-1] {
			t.Fatalf("index %d: primes list not strictly increasing (%d after %d)", i, p, primes[i-1])
		}
	}
}

func TestPassesTrialDivision(t *testing.T) {
	// A large number that's an obvious multiple of 3 must be rejected --
	// exact bit-shape doesn't matter for this check, only divisibility.
	multipleOfThree := new(big.Int).Mul(big.NewInt(3), new(big.Int).Lsh(bigOne, candidateBits-3))
	if PassesTrialDivision(multipleOfThree) {
		t.Fatal("a number divisible by 3 passed trial division")
	}

	// A real candidate drawn from the stream should, most of the time,
	// pass (only ~10% survive on average, but across several draws at
	// least one almost always will -- if this ever flakes it's a strong
	// signal something is fundamentally wrong with either candidate
	// generation or trial division).
	stream, err := NewSeedStream(fixedTestSeed())
	if err != nil {
		t.Fatal(err)
	}
	survived := false
	for i := 0; i < 100; i++ {
		c, err := GenerateCandidate(stream)
		if err != nil {
			t.Fatal(err)
		}
		if PassesTrialDivision(c) {
			survived = true
			break
		}
	}
	if !survived {
		t.Fatal("no candidate survived trial division in 100 draws (expected ~10)")
	}
}

// --- millerrabin.go: cross-validated against math/big's independent,
// differently-implemented ProbablyPrime as an oracle. We deliberately don't
// use stdlib ProbablyPrime in production (see millerrabin.go's doc comment
// for why), but it's an excellent independent check in tests specifically:
// if our hand-rolled Miller-Rabin ever disagreed with it, that would be a
// real bug worth catching immediately. ---------------------------------

func TestIsProbablyPrime_AgreesWithStdlibOracle(t *testing.T) {
	stream, err := NewSeedStream(fixedTestSeed())
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for checked < 20 {
		c, err := GenerateCandidate(stream)
		if err != nil {
			t.Fatal(err)
		}
		if !PassesTrialDivision(c) {
			continue
		}

		ours, err := IsProbablyPrime(c, stream)
		if err != nil {
			t.Fatal(err)
		}
		stdlib := c.ProbablyPrime(50)

		if ours != stdlib {
			t.Fatalf("disagreement with stdlib oracle for candidate %s: ours=%v stdlib=%v", c.Text(16), ours, stdlib)
		}
		checked++
	}
}

// --- primesearch.go + keyassembly.go + jwk.go: full pipeline -------------

// generateOnce runs the full pipeline exactly once for a given seed and
// applies every invariant check we have. Shared by the tests below so the
// (multi-second) generation cost is paid the minimum number of times.
func generateOnce(t *testing.T, seed string) *KeyGenResult {
	t.Helper()
	result, err := GenerateFromBitString(seed)
	if err != nil {
		t.Fatal(err)
	}

	if result.P.BitLen() != candidateBits || result.Q.BitLen() != candidateBits {
		t.Fatalf("p/q not exactly %d bits: p=%d q=%d", candidateBits, result.P.BitLen(), result.Q.BitLen())
	}
	if !result.P.ProbablyPrime(50) {
		t.Fatal("p disagrees with stdlib primality oracle")
	}
	if !result.Q.ProbablyPrime(50) {
		t.Fatal("q disagrees with stdlib primality oracle")
	}
	if result.P.Cmp(result.Q) == 0 {
		t.Fatal("p == q")
	}
	pMinus1 := new(big.Int).Sub(result.P, bigOne)
	qMinus1 := new(big.Int).Sub(result.Q, bigOne)
	if new(big.Int).GCD(nil, nil, publicExponent, pMinus1).Cmp(bigOne) != 0 {
		t.Fatal("gcd(e, p-1) != 1")
	}
	if new(big.Int).GCD(nil, nil, publicExponent, qMinus1).Cmp(bigOne) != 0 {
		t.Fatal("gcd(e, q-1) != 1")
	}

	if result.Key.N.BitLen() != 4096 {
		t.Fatalf("n bit length = %d, want 4096", result.Key.N.BitLen())
	}
	if len(result.Address) != 43 {
		t.Fatalf("address length = %d, want 43", len(result.Address))
	}

	// e*d == 1 (mod lambda(n)), the actual RSA correctness condition.
	lambda := new(big.Int).Div(
		new(big.Int).Mul(pMinus1, qMinus1),
		new(big.Int).GCD(nil, nil, pMinus1, qMinus1),
	)
	check := new(big.Int).Mod(new(big.Int).Mul(publicExponent, result.Key.D), lambda)
	if check.Cmp(bigOne) != 0 {
		t.Fatal("e*d != 1 (mod lambda(n)) -- d is not a valid private exponent")
	}

	// CRT parameters.
	if new(big.Int).Mod(result.Key.D, pMinus1).Cmp(result.Key.Dp) != 0 {
		t.Fatal("Dp != d mod (p-1)")
	}
	if new(big.Int).Mod(result.Key.D, qMinus1).Cmp(result.Key.Dq) != 0 {
		t.Fatal("Dq != d mod (q-1)")
	}
	if new(big.Int).Mod(new(big.Int).Mul(result.Key.Q, result.Key.Qi), result.P).Cmp(bigOne) != 0 {
		t.Fatal("Qi is not q^-1 mod p")
	}

	if err := SelfCheckTextbookRSA(result.Key); err != nil {
		t.Fatalf("SelfCheckTextbookRSA failed: %v", err)
	}

	return result
}

func TestGenerateFromBitString_FullPipeline(t *testing.T) {
	generateOnce(t, fixedTestSeed())
}

func TestGenerateFromBitString_Deterministic(t *testing.T) {
	seed := fixedTestSeed()
	r1 := generateOnce(t, seed)
	r2 := generateOnce(t, seed)

	if r1.Key.N.Cmp(r2.Key.N) != 0 {
		t.Fatal("same seed produced different n across two full pipeline runs")
	}
	if r1.Key.D.Cmp(r2.Key.D) != 0 {
		t.Fatal("same seed produced different d across two full pipeline runs")
	}
	if r1.Address != r2.Address {
		t.Fatalf("same seed produced different addresses: %s vs %s", r1.Address, r2.Address)
	}
}

func TestGenerateFromBitString_RejectsInvalidSeed(t *testing.T) {
	if _, err := GenerateFromBitString("not-a-bitstring"); err == nil {
		t.Fatal("expected an error for a malformed seed")
	}
}
