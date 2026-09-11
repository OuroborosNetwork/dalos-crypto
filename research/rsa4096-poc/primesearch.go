// This file ties steps 2-5 together: the guess-and-check loop that finds one
// 2048-bit prime (steps 2-4), then the pairwise safety checks FIPS 186-5
// requires once both primes are found (step 5). See
// /.docs/deterministic-rsa4096-from-seed.md §5.2-§5.2.7.
package main

import (
	"errors"
	"io"
	"math/big"
)

// publicExponent is the fixed, standard RSA public exponent e = 65537.
// Never derived from the seed or the primes -- see the chat log for why
// this specific number is universal practice.
var publicExponent = big.NewInt(65537)

// FindPrime repeatedly draws candidates from stream (step 2), filters them
// through trial division (step 3), and subjects survivors to Miller-Rabin
// (step 4), continuing on the SAME stream without ever rewinding or
// reseeding, until one passes -- AND satisfies gcd(e, candidate-1) == 1.
// That last check is a single-prime property (not pairwise), so it belongs
// here rather than in checkAuxiliaryConstraints: if it fails, we only need
// to throw away this one candidate and keep searching, not discard an
// already-found, already-valid partner prime too. (An earlier version of
// this code checked gcd(e, p-1) and gcd(e, q-1) only after BOTH primes had
// already been found, in the pairwise check -- which meant a ~1-in-65537
// single-prime failure wasted a perfectly good already-verified partner
// prime and its full Miller-Rabin search. Caught in review before this ever
// shipped anywhere; fixed here.)
//
// Returns the prime found and the number of candidates it took (useful for
// sanity-checking against the expected ~710-draw average from the density
// math).
func FindPrime(stream io.Reader) (*big.Int, int, error) {
	attempts := 0
	for {
		attempts++
		candidate, err := GenerateCandidate(stream)
		if err != nil {
			return nil, attempts, err
		}

		if !PassesTrialDivision(candidate) {
			continue
		}

		isPrime, err := IsProbablyPrime(candidate, stream)
		if err != nil {
			return nil, attempts, err
		}
		if !isPrime {
			continue
		}

		candidateMinus1 := new(big.Int).Sub(candidate, bigOne)
		if new(big.Int).GCD(nil, nil, publicExponent, candidateMinus1).Cmp(bigOne) != 0 {
			// gcd(e, candidate-1) != 1: this specific prime can't be used
			// with our fixed e (AssembleKey would have no inverse for it).
			// Astronomically rare (~1/65537 of primes), but when it does
			// happen the fix is to draw a fresh candidate, not to touch
			// whatever the OTHER prime search found.
			continue
		}

		return candidate, attempts, nil
	}
}

// minPrimeDistanceExponent implements the FIPS 186-5 auxiliary requirement
// that |p-q| be large enough to resist Fermat factorization: the standard
// bound is |p-q| > 2^(nlen/2 - 100), where nlen is the RSA modulus size (4096
// here), so nlen/2 = 2048 (the size of each prime) and the threshold is
// 2^(2048-100) = 2^1948.
const minPrimeDistanceExponent = candidateBits - 100

// checkAuxiliaryConstraints runs step 5's genuinely PAIRWISE safety checks
// against a candidate (p, q) pair -- properties that depend on both primes
// together, not on either one alone. (gcd(e, prime-1) is a single-prime
// property and lives in FindPrime instead -- see its comment for why.)
// Returns a non-nil error naming which check failed if any do; the caller's
// job is to discard BOTH primes and re-search, since a pairwise failure
// isn't attributable to just one of them.
func checkAuxiliaryConstraints(p, q *big.Int) error {
	if p.Cmp(q) == 0 {
		return errors.New("auxiliary check failed: p == q")
	}

	diff := new(big.Int).Sub(p, q)
	diff.Abs(diff)
	threshold := new(big.Int).Lsh(bigOne, minPrimeDistanceExponent)
	if diff.Cmp(threshold) <= 0 {
		return errors.New("auxiliary check failed: |p-q| too small (Fermat-factorization risk)")
	}

	return nil
}

// FindTwoPrimes runs the full step 2-5 pipeline on a single continuous
// stream: find p, then (without resetting anything) keep searching from
// wherever the stream is to find q, then validate the pair. If the pair
// fails an auxiliary check, BOTH primes are discarded and the search
// continues from the current stream position for a fresh pair -- the
// stream is never rewound, so every attempt (successful or not) permanently
// consumes stream material, exactly as the "structural, not statistical"
// correctness bar demands: nothing is ever reused or replayed.
func FindTwoPrimes(stream io.Reader) (p, q *big.Int, pAttempts, qAttempts int, err error) {
	for {
		p, pAttempts, err = FindPrime(stream)
		if err != nil {
			return nil, nil, 0, 0, err
		}
		q, qAttempts, err = FindPrime(stream)
		if err != nil {
			return nil, nil, 0, 0, err
		}

		if checkErr := checkAuxiliaryConstraints(p, q); checkErr == nil {
			return p, q, pAttempts, qAttempts, nil
		}
		// The pair failed a genuinely pairwise check (in practice this can
		// only be the |p-q| distance check now that gcd(e, prime-1) is
		// checked per-prime in FindPrime -- p==q is essentially impossible,
		// and a too-small |p-q| is very unlikely for independently-drawn
		// 2048-bit primes but not provably impossible). Both primes are
		// discarded together because the failure is a property of the pair,
		// not attributable to either one alone. Loop and draw a fresh pair
		// from further along the same stream.
	}
}
