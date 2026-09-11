package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// A fixed dummy 1600-bit seed for step 1/2 proof-of-concept only — NOT a
// real DALOS-generated seed, just 1600 deterministic-looking '0'/'1'
// characters so we have something the right shape to test with.
func dummySeedBitString() string {
	var sb strings.Builder
	pattern := "1101001011010110" // arbitrary 16-bit repeating pattern
	for sb.Len() < 1600 {
		sb.WriteString(pattern)
	}
	return sb.String()[:1600]
}

// A small set of fixed, distinct dummy seeds for the golden-vector run
// (step 9). Distinct repeating patterns so they're easy to eyeball as
// different inputs. NOT real DALOS seeds -- this whole file is a scratch
// prototype (see package doc in stream.go); real golden vectors get
// generated from real DALOS seed-word-derived bitstrings once this
// pipeline graduates out of research/rsa4096-poc into a real package.
func goldenTestSeeds() map[string]string {
	patterns := map[string]string{
		"seed-A": "1101001011010110",
		"seed-B": "0000000000000001",
		"seed-C": "1111111111111110",
		"seed-D": "1010101010101010",
		"seed-E": "0110100110010110",
	}
	seeds := make(map[string]string, len(patterns))
	for name, pattern := range patterns {
		var sb strings.Builder
		for sb.Len() < 1600 {
			sb.WriteString(pattern)
		}
		seeds[name] = sb.String()[:1600]
	}
	return seeds
}

func runStep1And2ProofOfConcept(seed string) {
	fmt.Println("=== Step 1 proof-of-concept: seed -> deterministic byte stream ===")
	fmt.Printf("seed length: %d bits\n\n", len(seed))

	r1, err := NewSeedStream(seed)
	if err != nil {
		panic(err)
	}
	r2, err := NewSeedStream(seed)
	if err != nil {
		panic(err)
	}

	buf1 := make([]byte, 4096)
	buf2 := make([]byte, 4096)
	if _, err := r1.Read(buf1); err != nil {
		panic(err)
	}
	if _, err := r2.Read(buf2); err != nil {
		panic(err)
	}

	if bytes.Equal(buf1, buf2) {
		fmt.Println("[PASS] two independent streams from the same seed produce identical bytes")
	} else {
		fmt.Println("[FAIL] streams diverged -- determinism broken")
	}
	fmt.Printf("first 32 bytes: %s\n\n", hex.EncodeToString(buf1[:32]))

	// Explicitly toggle the first character regardless of its current
	// value (rather than hardcoding "0" + seed[1:], which would silently
	// stop testing anything -- always comparing a stream against itself --
	// if dummySeedBitString's pattern is ever edited to start with '0').
	flippedFirstChar := byte('1')
	if seed[0] == '1' {
		flippedFirstChar = '0'
	}
	otherSeed := string(flippedFirstChar) + seed[1:]
	r3, err := NewSeedStream(otherSeed)
	if err != nil {
		panic(err)
	}
	buf3 := make([]byte, 32)
	if _, err := r3.Read(buf3); err != nil {
		panic(err)
	}
	if !bytes.Equal(buf1[:32], buf3) {
		fmt.Println("[PASS] flipping one seed bit produces a completely different stream")
	} else {
		fmt.Println("[FAIL] different seeds produced the same output")
	}
	fmt.Printf("flipped-seed first 32 bytes: %s\n\n", hex.EncodeToString(buf3))

	fmt.Println("=== Step 2 proof-of-concept: stream bytes -> bit-fixed candidate ===")
	streamForCandidates, err := NewSeedStream(seed)
	if err != nil {
		panic(err)
	}

	allOK := true
	for i := 0; i < 3; i++ {
		c, err := GenerateCandidate(streamForCandidates)
		if err != nil {
			panic(err)
		}
		bitLen := c.BitLen()
		isOdd := c.Bit(0) == 1
		top1 := c.Bit(candidateBits - 1)
		top2 := c.Bit(candidateBits - 2)
		ok := bitLen == candidateBits && isOdd && top1 == 1 && top2 == 1
		allOK = allOK && ok
		fmt.Printf("candidate %d: bitlen=%d odd=%v top-bit=%d second-top-bit=%d -> %s\n",
			i+1, bitLen, isOdd, top1, top2, passFail(ok))
	}
	if allOK {
		fmt.Println("[PASS] all candidates exactly 2048 bits, odd, top two bits set")
	}

	streamAgain, err := NewSeedStream(seed)
	if err != nil {
		panic(err)
	}
	firstAgain, err := GenerateCandidate(streamAgain)
	if err != nil {
		panic(err)
	}
	streamCheck, err := NewSeedStream(seed)
	if err != nil {
		panic(err)
	}
	firstCheck, err := GenerateCandidate(streamCheck)
	if err != nil {
		panic(err)
	}
	if firstAgain.Cmp(firstCheck) == 0 {
		fmt.Println("[PASS] first candidate is identical across two fresh streams from the same seed")
	} else {
		fmt.Println("[FAIL] first candidate diverged across runs -- determinism broken")
	}
	fmt.Println()
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func runFullPipelineDemo(seed string) *KeyGenResult {
	fmt.Println("=== Steps 3-6 + local step 8: full seed -> RSA-4096 JWK pipeline ===")
	start := time.Now()
	result, err := GenerateFullKey(seed)
	if err != nil {
		panic(err)
	}
	elapsed := time.Since(start)

	fmt.Printf("p found after %d candidate draws, q found after %d candidate draws\n", result.PAttempts, result.QAttempts)
	fmt.Printf("(expected average ~710 draws per prime from the density math -- both should be same order of magnitude, not proof of a bug if they differ by a few hundred either way)\n")
	fmt.Printf("wall-clock time: %s\n", elapsed)
	fmt.Printf("n bit-length: %d (must be exactly 4096)\n", result.Key.N.BitLen())
	fmt.Printf("address: %s (must be exactly 43 base64url characters)\n", result.Address)
	fmt.Printf("address length: %d chars -> %s\n\n", len(result.Address), passFail(len(result.Address) == 43))

	if err := SelfCheckTextbookRSA(result.Key); err != nil {
		fmt.Printf("[FAIL] textbook RSA self-check: %v\n\n", err)
		panic(err) // this must never fail; treat as fatal if it does
	}
	fmt.Println("[PASS] textbook RSA round-trip (encrypt/decrypt AND sign/verify) correct for 4 test messages")
	fmt.Println()

	// Determinism check across the full pipeline: same seed run twice must
	// give byte-identical JWKs.
	result2, err := GenerateFullKey(seed)
	if err != nil {
		panic(err)
	}
	same := result.Key.N.Cmp(result2.Key.N) == 0 && result.Key.D.Cmp(result2.Key.D) == 0
	fmt.Printf("[%s] same seed run twice through the FULL pipeline produces identical n and d\n\n", passFail(same))
	if !same {
		panic("full-pipeline determinism broken")
	}

	return result
}

func writeJSON(path string, v interface{}) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
}

func main() {
	seed := dummySeedBitString()
	runStep1And2ProofOfConcept(seed)
	result := runFullPipelineDemo(seed)

	// Write this seed's JWK out for the Node/real-arweave-core cross-check
	// (validate.mjs) -- the part of step 8 that involves a real, independent
	// implementation rather than just our own internal arithmetic sanity
	// check.
	writeJSON("jwk.json", result.JWK)
	fmt.Println("wrote jwk.json for external validation (run: node validate.mjs)")

	// Step 9: golden test vectors. A handful of fixed seeds, run through the
	// full pipeline once, locked in as the frozen expected output. NOTE:
	// these are prototype-stage vectors from dummy (non-DALOS) seeds --
	// real, frozen-forever golden vectors get (re)generated from actual
	// DALOS seed-word-derived bitstrings when this graduates out of
	// research/rsa4096-poc (steps 10-11, tomorrow).
	fmt.Println("\n=== Step 9: golden test vectors (prototype-stage, dummy seeds) ===")
	type goldenVector struct {
		SeedName  string `json:"seed_name"`
		Seed      string `json:"seed_bitstring"`
		Address   string `json:"address"`
		JWK       *JWK   `json:"jwk"`
		PAttempts int    `json:"p_attempts"`
		QAttempts int    `json:"q_attempts"`
	}
	seeds := goldenTestSeeds()
	names := make([]string, 0, len(seeds))
	for name := range seeds {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic ordering -- map iteration order is not

	var vectors []goldenVector
	for _, name := range names {
		s := seeds[name]
		r, err := GenerateFullKey(s)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s: address=%s (p_attempts=%d, q_attempts=%d)\n", name, r.Address, r.PAttempts, r.QAttempts)
		vectors = append(vectors, goldenVector{
			SeedName:  name,
			Seed:      s,
			Address:   r.Address,
			JWK:       r.JWK,
			PAttempts: r.PAttempts,
			QAttempts: r.QAttempts,
		})
	}
	writeJSON("golden_vectors.json", vectors)
	fmt.Println("wrote golden_vectors.json")
}
