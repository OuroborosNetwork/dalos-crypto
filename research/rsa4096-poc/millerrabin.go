// This file implements STEP 4 of the plan: the real primality test. Plain
// Miller-Rabin, deliberately NOT math/big.Int.ProbablyPrime -- see Decision
// Record §8.2 for why: ProbablyPrime seeds its own witness selection from
// Go-internal math/rand keyed off the candidate value itself, which (a) is
// Go-specific plumbing that doesn't port to TypeScript, and (b) isn't tied
// to OUR seeded stream, breaking the "every random draw traceable to the one
// seed" correctness bar from the design doc. This hand-rolled version uses
// math/big ONLY for arithmetic (Exp, Mod, comparisons) -- never for
// randomness -- and draws every witness from the seed stream.
package main

import (
	"errors"
	"io"
	"math/big"
)

// millerRabinRounds is deliberately over-provisioned (design doc §5.2 step
// 4 calls for 64-100 rounds). Each round independently has at most a 1-in-4
// chance of a composite slipping through; 64 rounds pushes the false-positive
// probability to at most 4^-64, far below any other real-world failure mode
// in the system.
const millerRabinRounds = 64

var (
	bigOne = big.NewInt(1)
	bigTwo = big.NewInt(2)
)

// generateWitness draws a fresh Miller-Rabin witness `a` in the range
// [2, n-2] from stream, given nMinus3 = n-3 (precomputed once per candidate
// by the caller, since it's invariant across all millerRabinRounds calls --
// no reason to recompute the same subtraction 64 times).
//
// USES REJECTION SAMPLING, NOT `raw mod (n-3)` -- caught in review: a naive
// modulo reduction is BIASED here. candidateBytes (256 bytes = 2048 bits) of
// stream output is uniform over [0, 2^2048), but n-3 does not evenly divide
// 2^2048, so `raw mod (n-3)` would over-represent the low end of [2, n-2] by
// a real, quantifiable amount -- and every candidate this codebase ever
// produces has its top two bits forced to 1 (GenerateCandidate), so n always
// sits in the narrow range [0.75 x 2^2048, 2^2048), which is exactly the
// range where this bias is largest. Rejection sampling eliminates it
// entirely: draw raw, and ONLY accept it if raw < n-3 (discard and draw a
// fresh 256 bytes otherwise). Since n-3 is always >= ~0.75 x 2^2048, the
// rejection rate is small (at most ~25%, usually far less), so this costs at
// most a small constant number of extra stream reads per witness, never
// more.
//
// This is the SAME 2048-bit-draw shape as GenerateCandidate. Every draw --
// accepted or rejected -- consumes a genuinely fresh 256 bytes from the
// stream; a rejected draw's bytes are simply never revisited, consistent
// with "never reuse, never rewind."
//
// PORTABILITY NOTE for the future TypeScript port: this must be reproduced
// EXACTLY --
//  1. read candidateBytes (256) bytes from the stream as a big-endian
//     unsigned integer (no bit-fixing -- unlike GenerateCandidate, a witness
//     does NOT need to be odd or a specific bit length).
//  2. if raw >= (n - 3): DISCARD raw, read a fresh 256 bytes, and retry.
//     Do NOT reduce the rejected value with mod -- that's precisely the bias
//     this rejection loop exists to avoid.
//  3. once raw < (n - 3): the witness is (raw + 2), landing it in [2, n-2].
//
// Both Go's math/big.Int and JS's native BigInt support arbitrary-precision
// comparison and addition directly, so this is expressible identically in
// both languages with no hidden platform-specific behavior, and -- unlike
// the modulo version -- no risk of a subtly different reduction formula
// creeping in between the two ports.
func generateWitness(stream io.Reader, nMinus3 *big.Int) (*big.Int, error) {
	for {
		buf := make([]byte, candidateBytes)
		if _, err := io.ReadFull(stream, buf); err != nil {
			return nil, errors.New("generateWitness: failed to read from seed stream: " + err.Error())
		}
		raw := new(big.Int).SetBytes(buf)

		if raw.Cmp(nMinus3) < 0 {
			return raw.Add(raw, bigTwo), nil
		}
		// raw >= n-3: outside the unbiased range for this modulus, discard
		// and draw fresh bytes on the next loop iteration.
	}
}

// IsProbablyPrime runs millerRabinRounds independent Miller-Rabin rounds
// against candidate, with every witness drawn from stream. Returns false the
// instant any round proves compositeness (no wasted rounds on an obvious
// composite); returns true only if every round agrees "no evidence of
// compositeness found."
//
// Precondition: candidate must be odd and > 3 (always true for anything
// that came out of GenerateCandidate).
func IsProbablyPrime(candidate *big.Int, stream io.Reader) (bool, error) {
	nMinus1 := new(big.Int).Sub(candidate, bigOne)

	// Factor nMinus1 = 2^k * m, with m odd.
	k := 0
	m := new(big.Int).Set(nMinus1)
	for m.Bit(0) == 0 { // while m is even
		m.Rsh(m, 1)
		k++
	}

	nMinus3 := new(big.Int).Sub(candidate, big.NewInt(3))

	for round := 0; round < millerRabinRounds; round++ {
		a, err := generateWitness(stream, nMinus3)
		if err != nil {
			return false, err
		}

		x := new(big.Int).Exp(a, m, candidate) // x = a^m mod candidate

		if x.Cmp(bigOne) == 0 || x.Cmp(nMinus1) == 0 {
			continue // this round found no evidence of compositeness
		}

		composite := true
		for j := 0; j < k-1; j++ {
			x.Mod(x.Mul(x, x), candidate) // x = x^2 mod candidate
			if x.Cmp(nMinus1) == 0 {
				composite = false
				break
			}
			if x.Cmp(bigOne) == 0 {
				// Nontrivial square root of 1 -- mathematical proof of
				// compositeness, no need to check further.
				return false, nil
			}
		}
		if composite {
			return false, nil
		}
	}

	return true, nil
}
