// This file implements STEP 3 of the plan: a cheap trial-division bouncer
// that rejects obviously-composite candidates before they ever reach the
// expensive Miller-Rabin test (candidate.go / millerrabin.go). See the
// Decision Record in /.docs/deterministic-rsa4096-from-seed.md §8 for the
// cost-model derivation of why ~2000 small primes is the right cutoff.
package RSA4096

import "math/big"

// SmallPrimeCount is the number of small odd primes we trial-divide by.
// Chosen from an explicit cost-model computation (see chat log / decision
// record): the optimum for 2048-bit candidates sits around ~1400 primes
// (bound ~11700) with a very flat curve out to ~2000 primes (bound ~17900);
// 2000 was picked as a clean round number solidly inside that flat optimum,
// deliberately NOT hardcoded as a literal list (see reasoning below).
const SmallPrimeCount = 2000

// smallOddPrimes returns the first n odd primes (2 is excluded on purpose:
// every candidate from GenerateCandidate has its bottom bit forced to 1, so
// it is odd by construction and testing divisibility by 2 can never reject
// anything).
//
// DELIBERATE DESIGN CHOICE: computed via a plain Sieve of Eratosthenes at
// call time, NOT hardcoded as a literal array. Reasons (see chat log):
//   - Speed is a non-issue: sieving to ~18000 is sub-millisecond, dwarfed by
//     everything else in the pipeline.
//   - A ~15-line sieve is trivially auditable by reading it; a 2000-entry
//     hardcoded array is not something anyone will actually eyeball-verify.
//   - Cross-language safety: this must be reimplemented in TypeScript later.
//     A sieve algorithm is easy to write identically in both languages with
//     zero risk of drift. Two independently-maintained 2000-entry literal
//     arrays are a realistic place for the Go and TS sides to silently
//     diverge by one entry -- exactly the class of bug this whole project
//     is designed to eliminate everywhere else.
func smallOddPrimes(n int) []uint64 {
	if n <= 0 {
		return nil
	}

	// Upper bound estimate for the n-th prime (Rosser's theorem, valid for
	// n >= 6): p_n < n * (ln(n) + ln(ln(n))). Padded generously since we'd
	// rather over-sieve once than under-sieve and have to grow.
	bound := 1000
	for {
		primes := sieveOfEratosthenes(bound)
		odd := make([]uint64, 0, n)
		for _, p := range primes {
			if p == 2 {
				continue
			}
			odd = append(odd, p)
			if len(odd) == n {
				return odd
			}
		}
		bound *= 2 // under-estimated; grow and resieve.
	}
}

// sieveOfEratosthenes returns every prime <= limit, in increasing order.
func sieveOfEratosthenes(limit int) []uint64 {
	if limit < 2 {
		return nil
	}
	isComposite := make([]bool, limit+1)
	var primes []uint64
	for i := 2; i <= limit; i++ {
		if isComposite[i] {
			continue
		}
		primes = append(primes, uint64(i))
		for j := i * i; j <= limit; j += i {
			isComposite[j] = true
		}
	}
	return primes
}

// smallOddPrimesCache is computed once (the sieve is cheap, but there is no
// reason to redo it for every candidate across the whole search).
var smallOddPrimesCache = smallOddPrimes(SmallPrimeCount)

// smallOddPrimesBigIntCache pre-boxes each entry of smallOddPrimesCache into
// a *big.Int once, instead of allocating a fresh one on every trial-division
// check. PassesTrialDivision runs on nearly every candidate drawn (it's the
// first-line filter), so across a full key generation this divisor list is
// consulted on the order of a few thousand candidates x SmallPrimeCount
// primes -- reusing the same *big.Int values avoids millions of avoidable
// short-lived allocations. (Caught in review before this ever ran at scale.)
var smallOddPrimesBigIntCache = func() []*big.Int {
	out := make([]*big.Int, len(smallOddPrimesCache))
	for i, p := range smallOddPrimesCache {
		out[i] = new(big.Int).SetUint64(p)
	}
	return out
}()

// PassesTrialDivision reports whether candidate is NOT divisible by any of
// the first SmallPrimeCount odd primes. false means "definitely composite,
// reject without spending a single Miller-Rabin round." true means "survived
// the cheap filter, now worth the expensive real test."
//
// This can never produce a false rejection: every value in smallOddPrimesCache
// is a genuine prime, and candidate (a 2048-bit number) is always far larger
// than any of them, so an exact-equality edge case never arises.
func PassesTrialDivision(candidate *big.Int) bool {
	mod := new(big.Int)
	for _, p := range smallOddPrimesBigIntCache {
		mod.Mod(candidate, p)
		if mod.Sign() == 0 {
			return false
		}
	}
	return true
}
