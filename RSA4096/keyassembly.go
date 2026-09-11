// This file implements STEPS 6 and 7 of the plan: turning two validated
// primes into the full set of numbers a real RSA-4096 JWK needs, using the
// λ(n) (Carmichael) convention -- empirically confirmed to match what
// OpenSSL (and therefore Node/browser WebCrypto, and therefore
// arweave-core's actual `generateKey()`) produces. See the chat log's
// empirical verification (openssl genrsa + inspecting privateExponent
// against phi(n) and lambda(n)) and Decision Record for the full reasoning:
// this choice does not affect correctness (both conventions produce a
// working key) or interop (arweave-core's importKeyfile never validates
// d/p/q consistency, and the Arweave address depends only on n) -- it's
// chosen purely to match real-world convention and to give the eventual
// Go/TypeScript ports one unambiguous formula to agree on.
package RSA4096

import (
	"errors"
	"math/big"
)

// RSAKey holds every field a canonical Arweave JWK needs, as big.Int. See
// jwk.go for the base64url-JWK-shaped encoding of this struct.
type RSAKey struct {
	N  *big.Int // modulus, p*q
	E  *big.Int // public exponent, fixed 65537
	D  *big.Int // private exponent, e^-1 mod lambda(n)
	P  *big.Int
	Q  *big.Int
	Dp *big.Int // d mod (p-1) -- CRT shortcut
	Dq *big.Int // d mod (q-1) -- CRT shortcut
	Qi *big.Int // q^-1 mod p  -- CRT shortcut
}

// AssembleKey computes every value a canonical RSA-4096 JWK needs from two
// already-validated primes (output of FindTwoPrimes). Pure arithmetic --
// no randomness, no stream reads, nothing left to determinism-audit beyond
// "is this formula implemented identically in Go and TypeScript."
func AssembleKey(p, q *big.Int) (*RSAKey, error) {
	n := new(big.Int).Mul(p, q)

	pMinus1 := new(big.Int).Sub(p, bigOne)
	qMinus1 := new(big.Int).Sub(q, bigOne)

	gcd := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
	lcm := new(big.Int).Div(new(big.Int).Mul(pMinus1, qMinus1), gcd) // lambda(n) = lcm(p-1, q-1)

	d := new(big.Int).ModInverse(publicExponent, lcm)
	if d == nil {
		// ModInverse returns nil if e and lambda(n) share a common factor.
		// checkAuxiliaryConstraints (primesearch.go) already verified
		// gcd(e, p-1) == 1 and gcd(e, q-1) == 1 individually, which implies
		// gcd(e, lambda(n)) == 1 too (lambda(n) = lcm(p-1,q-1) shares no
		// prime factor with e that either p-1 or q-1 doesn't already have).
		// Reaching this branch would mean that guarantee was violated --
		// treat it as a fatal invariant break, not a retryable condition.
		return nil, errors.New("AssembleKey: e has no inverse mod lambda(n) -- auxiliary check invariant violated")
	}

	dp := new(big.Int).Mod(d, pMinus1)
	dq := new(big.Int).Mod(d, qMinus1)

	qi := new(big.Int).ModInverse(q, p)
	if qi == nil {
		return nil, errors.New("AssembleKey: q has no inverse mod p -- should be impossible for distinct primes")
	}

	return &RSAKey{
		N: n,
		// A fresh copy, NOT the shared publicExponent pointer: every RSAKey
		// this function ever produces (across every seed, in the same
		// process -- see main.go's golden-vector loop, which calls this
		// repeatedly) must own independent big.Int values. Aliasing the
		// package-level singleton here is dormant today (nothing currently
		// mutates key.E in place) but this repo has an established
		// "zero sensitive big.Ints after use" hygiene convention (KG-3,
		// v2.1.0) -- if that's ever bolted onto RSAKey, zeroing one key's
		// E would silently zero every other key's E too. Caught in review.
		E:  new(big.Int).Set(publicExponent),
		D:  d,
		P:  p,
		Q:  q,
		Dp: dp,
		Dq: dq,
		Qi: qi,
	}, nil
}
