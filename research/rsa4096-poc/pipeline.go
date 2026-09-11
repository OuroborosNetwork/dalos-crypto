// This file wires steps 1-8 together into one callable pipeline, plus a
// self-contained "textbook RSA" correctness check that doesn't depend on any
// external library: encrypt/decrypt a test message with the raw (n, e, d)
// numbers and confirm it round-trips. This is independent of, and a
// necessary-but-not-sufficient complement to, the external Node/WebCrypto +
// real arweave-core cross-validation done by validate.mjs.
package main

import (
	"errors"
	"math/big"
)

// KeyGenResult bundles everything produced by one full run of the pipeline,
// for reporting and for writing out golden vectors (step 9).
type KeyGenResult struct {
	Seed        string
	P, Q        *big.Int
	Key         *RSAKey
	JWK         *JWK
	Address     string
	PAttempts   int
	QAttempts   int
}

// GenerateFullKey runs the complete seed -> RSA-4096 JWK pipeline (steps
// 1 through 6, plus the local half of step 8): open the seed stream, find
// two validated primes, assemble the key, encode the JWK, derive the
// address.
func GenerateFullKey(seedBitString string) (*KeyGenResult, error) {
	stream, err := NewSeedStream(seedBitString)
	if err != nil {
		return nil, err
	}

	p, q, pAttempts, qAttempts, err := FindTwoPrimes(stream)
	if err != nil {
		return nil, err
	}

	key, err := AssembleKey(p, q)
	if err != nil {
		return nil, err
	}

	jwk, err := key.ToJWK()
	if err != nil {
		return nil, err
	}

	address, err := AddressOf(key.N)
	if err != nil {
		return nil, err
	}

	return &KeyGenResult{
		Seed:      seedBitString,
		P:         p,
		Q:         q,
		Key:       key,
		JWK:       jwk,
		Address:   address,
		PAttempts: pAttempts,
		QAttempts: qAttempts,
	}, nil
}

// SelfCheckTextbookRSA verifies that d is genuinely the correct private
// exponent for (n, e) by round-tripping several test messages through raw
// (unpadded) RSA: c = m^e mod n, m' = c^d mod n, and checking m' == m. This
// is deliberately independent of any padding scheme (RSA-PSS, PKCS#1 v1.5,
// etc.) -- it isolates and proves the one thing that could actually be
// wrong at this stage: whether AssembleKey computed a mathematically
// correct d. Padding-scheme correctness is exercised separately by
// validate.mjs against real WebCrypto RSA-PSS.
func SelfCheckTextbookRSA(key *RSAKey) error {
	testMessages := []int64{2, 3, 1234567, 987654321}
	for _, mVal := range testMessages {
		m := big.NewInt(mVal)
		if m.Cmp(key.N) >= 0 {
			return errors.New("SelfCheckTextbookRSA: test message >= n, test is malformed")
		}

		c := new(big.Int).Exp(m, key.E, key.N)   // encrypt: c = m^e mod n
		mPrime := new(big.Int).Exp(c, key.D, key.N) // decrypt: m' = c^d mod n

		if m.Cmp(mPrime) != 0 {
			return errors.New("SelfCheckTextbookRSA: round-trip FAILED for message " + m.String() + " -- d is not the correct inverse of e")
		}

		// Also confirm signing direction (sign with d, verify with e) --
		// for RSA these are the same operation mathematically (m^d mod n
		// then result^e mod n), but worth checking explicitly since that's
		// the operation actually used for Arweave transaction signing.
		s := new(big.Int).Exp(m, key.D, key.N)
		mFromSig := new(big.Int).Exp(s, key.E, key.N)
		if m.Cmp(mFromSig) != 0 {
			return errors.New("SelfCheckTextbookRSA: sign/verify round-trip FAILED for message " + m.String())
		}
	}
	return nil
}
