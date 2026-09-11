/**
 * Ties the candidate/trial-division/Miller-Rabin pieces together into a
 * full prime search, then the FIPS 186-5 pairwise safety checks. Direct
 * port of RSA4096/primesearch.go -- see that file's doc comments for the
 * reasoning behind the single-prime-vs-pairwise check split (a review
 * finding on the Go side, ported here already fixed).
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Blake3XofStream } from '../dalos-blake3/index.js';
import { gcd } from './bigint-math.js';
import { CANDIDATE_BITS, generateCandidate } from './candidate.js';
import { isProbablyPrime } from './millerrabin.js';
import { passesTrialDivision } from './primes.js';

/** Fixed, standard RSA public exponent e = 65537. Matches RSA4096/primesearch.go. */
export const PUBLIC_EXPONENT = 65537n;

export interface FindPrimeResult {
  prime: bigint;
  attempts: number;
}

/**
 * Repeatedly draws candidates from `stream`, filters through trial
 * division, subjects survivors to Miller-Rabin, and checks
 * gcd(e, candidate-1) == 1 -- a single-prime property, checked here (not
 * in the pairwise check) so a failure only costs redrawing this one
 * candidate. Matches RSA4096/primesearch.go's FindPrime exactly.
 */
export function findPrime(stream: Blake3XofStream): FindPrimeResult {
  let attempts = 0;
  for (;;) {
    attempts++;
    const candidate = generateCandidate(stream);

    if (!passesTrialDivision(candidate)) {
      continue;
    }

    if (!isProbablyPrime(candidate, stream)) {
      continue;
    }

    const candidateMinus1 = candidate - 1n;
    if (gcd(PUBLIC_EXPONENT, candidateMinus1) !== 1n) {
      // gcd(e, candidate-1) != 1: astronomically rare (~1/65537 of
      // primes); draw a fresh candidate, don't touch the OTHER prime's
      // search.
      continue;
    }

    return { prime: candidate, attempts };
  }
}

/**
 * FIPS 186-5's |p-q| > 2^(nlen/2 - 100) bound: nlen = 4096 (the RSA
 * modulus size), nlen/2 = 2048 = CANDIDATE_BITS (the size of each prime),
 * so the threshold is 2^(2048-100) = 2^1948. Matches
 * RSA4096/primesearch.go's minPrimeDistanceExponent.
 */
const MIN_PRIME_DISTANCE_EXPONENT = BigInt(CANDIDATE_BITS - 100);

/**
 * Runs the genuinely PAIRWISE safety checks (p != q, |p-q| large enough)
 * against a candidate (p, q) pair. Matches RSA4096/primesearch.go's
 * checkAuxiliaryConstraints exactly (gcd(e, prime-1) is a single-prime
 * property and lives in findPrime instead).
 */
function passesAuxiliaryConstraints(p: bigint, q: bigint): boolean {
  if (p === q) {
    return false;
  }
  const diff = p > q ? p - q : q - p;
  const threshold = 1n << MIN_PRIME_DISTANCE_EXPONENT;
  return diff > threshold;
}

export interface FindTwoPrimesResult {
  p: bigint;
  q: bigint;
  pAttempts: number;
  qAttempts: number;
}

/**
 * Runs the full search on a single continuous stream: find p, then
 * (without resetting anything) keep searching from wherever the stream is
 * to find q, then validate the pair. On a pairwise-check failure, keeps
 * `p` and redraws only `q` -- matches RSA4096/primesearch.go's
 * FindTwoPrimes exactly.
 */
export function findTwoPrimes(stream: Blake3XofStream): FindTwoPrimesResult {
  const { prime: p, attempts: pAttempts } = findPrime(stream);

  for (;;) {
    const { prime: q, attempts: qAttempts } = findPrime(stream);
    if (passesAuxiliaryConstraints(p, q)) {
      return { p, q, pAttempts, qAttempts };
    }
    // Pairwise check failed (in practice, only the |p-q| distance check
    // can fire now that gcd(e, prime-1) is checked per-prime -- p===q is
    // essentially impossible, and a too-small |p-q| is very unlikely for
    // independently-drawn 2048-bit primes but not provably impossible).
    // Keep p, draw a fresh q from further along the same stream.
  }
}
