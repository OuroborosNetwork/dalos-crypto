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
import {
  type ProgressCallback,
  type ProgressStage,
  STAGE_SEARCHING_P,
  STAGE_SEARCHING_Q,
  reportProgress,
} from './progress.js';

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
 *
 * `stage` and `onProgress` are purely observational (see progress.ts):
 * `onProgress`, if provided, is called once per candidate draw with the
 * current attempt count and a probabilistic completion estimate. Omitting
 * it (every internal caller in this package's own tests does) skips the
 * estimate computation entirely and reproduces byte-for-byte the exact
 * same `{prime, attempts}` as before progress reporting existed.
 */
export function findPrime(
  stream: Blake3XofStream,
  stage: ProgressStage,
  onProgress?: ProgressCallback,
): FindPrimeResult {
  let attempts = 0;
  for (;;) {
    attempts++;
    reportProgress(onProgress, stage, attempts);

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
export function passesAuxiliaryConstraints(p: bigint, q: bigint): boolean {
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
export function findTwoPrimes(
  stream: Blake3XofStream,
  onProgress?: ProgressCallback,
): FindTwoPrimesResult {
  const { prime: p, attempts: pAttempts } = findPrime(stream, STAGE_SEARCHING_P, onProgress);

  for (;;) {
    const { prime: q, attempts: qAttempts } = findPrime(stream, STAGE_SEARCHING_Q, onProgress);
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

// --- Async variants: for a UI progress bar that must actually repaint ---
//
// Progress reporting alone (findPrime/findTwoPrimes above) is NOT enough
// to drive a smoothly-updating browser progress bar: RSA-4096 generation
// is CPU-bound native-BigInt arithmetic, and JavaScript's single-threaded
// event loop cannot repaint the DOM while a long synchronous function is
// still running, no matter how many times it calls a callback internally.
// The callback fires, but the browser can't draw the frame until control
// returns to the event loop.
//
// findPrimeAsync mirrors findPrime's body byte-for-byte, with exactly one
// addition: `if ((attempts & 0x07) === 0) await yieldToEventLoop();` --
// the same "yield every 8 iterations, triggered only by a public,
// data-independent counter" pattern already established in this repo for
// scalarMultiplierAsync/schnorrSignAsync (see gen1/scalar-mult.ts). The
// two bodies are kept as parallel, near-identical functions rather than
// unified into one generic yielding abstraction -- deliberately, so
// either can be read start-to-finish and audited against the other by
// direct comparison, matching this codebase's existing convention.

/**
 * Yields control to the event loop via `setImmediate` (Node) or
 * `setTimeout(_, 0)` (browser/Deno fallback) -- identical mechanism to
 * gen1/scalar-mult.ts's module-private helper of the same name (that one
 * is not exported, so it can't be imported and shared; this is a second,
 * independent copy of the same three lines, not a meaningful duplication
 * risk since there is nothing to keep "in sync" -- it's a fixed platform
 * API call).
 */
function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    const g = globalThis as { setImmediate?: (cb: () => void) => void };
    if (typeof g.setImmediate === 'function') {
      g.setImmediate(resolve);
    } else {
      setTimeout(resolve, 0);
    }
  });
}

/**
 * Async mirror of findPrime -- same search, same result, but yields to
 * the event loop every 8 candidate draws so a UI progress bar can
 * actually repaint during the search. See the section comment above for
 * why this is a separate function rather than a flag on findPrime.
 */
export async function findPrimeAsync(
  stream: Blake3XofStream,
  stage: ProgressStage,
  onProgress?: ProgressCallback,
): Promise<FindPrimeResult> {
  let attempts = 0;
  for (;;) {
    attempts++;
    reportProgress(onProgress, stage, attempts);
    if ((attempts & 0x07) === 0) {
      await yieldToEventLoop();
    }

    const candidate = generateCandidate(stream);

    if (!passesTrialDivision(candidate)) {
      continue;
    }

    if (!isProbablyPrime(candidate, stream)) {
      continue;
    }

    const candidateMinus1 = candidate - 1n;
    if (gcd(PUBLIC_EXPONENT, candidateMinus1) !== 1n) {
      continue;
    }

    return { prime: candidate, attempts };
  }
}

/** Async mirror of findTwoPrimes, built on findPrimeAsync. */
export async function findTwoPrimesAsync(
  stream: Blake3XofStream,
  onProgress?: ProgressCallback,
): Promise<FindTwoPrimesResult> {
  const { prime: p, attempts: pAttempts } = await findPrimeAsync(
    stream,
    STAGE_SEARCHING_P,
    onProgress,
  );

  for (;;) {
    const { prime: q, attempts: qAttempts } = await findPrimeAsync(
      stream,
      STAGE_SEARCHING_Q,
      onProgress,
    );
    if (passesAuxiliaryConstraints(p, q)) {
      return { p, q, pAttempts, qAttempts };
    }
  }
}
