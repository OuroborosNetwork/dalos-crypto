/**
 * Two validated primes -> every number a real RSA-4096 JWK needs, using
 * the λ(n) (Carmichael) convention -- empirically confirmed (this
 * session, against a real `openssl genrsa` output) to match what OpenSSL
 * (and therefore Node/browser WebCrypto, and therefore arweave-core's
 * actual `generateKey()`) produces. Direct port of RSA4096/keyassembly.go
 * -- see that file's doc comment, and
 * /.docs/deterministic-rsa4096-from-seed.md §9.2, for the full reasoning:
 * this choice doesn't affect correctness (both φ(n) and λ(n) conventions
 * produce a working key) or interop (arweave-core's importKeyfile never
 * validates d/p/q consistency, and the Arweave address depends only on
 * n) -- it's chosen purely to match real-world convention and to give
 * the Go and TS ports one unambiguous formula to agree on.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { gcd, modInverse } from './bigint-math.js';
import { PUBLIC_EXPONENT } from './primesearch.js';

/** Every field a canonical Arweave JWK needs, as bigint. See jwk.ts for encoding. */
export interface RSAKey {
  n: bigint; // modulus, p*q
  e: bigint; // public exponent, fixed 65537
  d: bigint; // private exponent, e^-1 mod lambda(n)
  p: bigint;
  q: bigint;
  dp: bigint; // d mod (p-1) -- CRT shortcut
  dq: bigint; // d mod (q-1) -- CRT shortcut
  qi: bigint; // q^-1 mod p  -- CRT shortcut
}

/**
 * Computes every value a canonical RSA-4096 JWK needs from two
 * already-validated primes (output of findTwoPrimes). Pure arithmetic --
 * no randomness, nothing left to determinism-audit beyond "is this
 * formula implemented identically in Go and TypeScript." Matches
 * RSA4096/keyassembly.go's AssembleKey exactly.
 */
export function assembleKey(p: bigint, q: bigint): RSAKey {
  const n = p * q;

  const pMinus1 = p - 1n;
  const qMinus1 = q - 1n;

  const g = gcd(pMinus1, qMinus1);
  const lambda = (pMinus1 * qMinus1) / g; // lambda(n) = lcm(p-1, q-1)

  const d = modInverse(PUBLIC_EXPONENT, lambda);
  if (d === null) {
    // findPrime already verified gcd(e, p-1) == 1 and gcd(e, q-1) == 1
    // individually, which implies gcd(e, lambda(n)) == 1 too. Reaching
    // this branch would mean that guarantee was violated -- treat it as
    // a fatal invariant break, matching RSA4096/keyassembly.go.
    throw new Error(
      'assembleKey: e has no inverse mod lambda(n) -- auxiliary check invariant violated',
    );
  }

  const dp = ((d % pMinus1) + pMinus1) % pMinus1;
  const dq = ((d % qMinus1) + qMinus1) % qMinus1;

  const qi = modInverse(q, p);
  if (qi === null) {
    throw new Error(
      'assembleKey: q has no inverse mod p -- should be impossible for distinct primes',
    );
  }

  return { n, e: PUBLIC_EXPONENT, d, p, q, dp, dq, qi };
}
