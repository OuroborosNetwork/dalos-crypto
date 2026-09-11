/**
 * The real primality test. Direct port of RSA4096/millerrabin.go -- plain
 * Miller-Rabin, witnesses drawn from the seed stream via rejection
 * sampling (NOT `mod`, which would be measurably biased -- see that
 * file's doc comment, and /.docs/deterministic-rsa4096-from-seed.md §9.3,
 * for why this specific bug was caught and fixed before this ever shipped
 * anywhere).
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Blake3XofStream } from '../dalos-blake3/index.js';
import { bytesToBigInt, modPow } from './bigint-math.js';
import { CANDIDATE_BYTES } from './candidate.js';

/**
 * Deliberately over-provisioned (design doc §5.2 step 4 calls for 64-100
 * rounds; set to the top of that range, 100, since key generation is a
 * one-time operation per seed -- no per-transaction cost to amortize, so
 * no reason not to buy the extra margin). Matches RSA4096/millerrabin.go's
 * MillerRabinRounds exactly -- this MUST stay in sync with the Go side; a
 * mismatch would mean the two implementations draw a different number of
 * stream bytes confirming each accepted prime, breaking cross-language
 * byte-identity. Changing this value changes testvectors/v2_rsa4096.json's
 * frozen output (see that file's own regeneration procedure).
 */
export const MILLER_RABIN_ROUNDS = 100;

/**
 * Draws a fresh Miller-Rabin witness `a` in the range [2, n-2] from
 * `stream`, given `nMinus3` = n-3 (precomputed once per candidate by the
 * caller). Uses rejection sampling, NOT `raw mod (n-3)` -- matches
 * RSA4096/millerrabin.go's generateWitness exactly; see that file for the
 * bias proof this avoids.
 */
function generateWitness(stream: Blake3XofStream, nMinus3: bigint): bigint {
  for (;;) {
    const raw = bytesToBigInt(stream.read(CANDIDATE_BYTES));
    if (raw < nMinus3) {
      return raw + 2n;
    }
    // raw >= n-3: outside the unbiased range for this modulus, discard
    // and draw fresh bytes on the next loop iteration.
  }
}

/**
 * Runs {@link MILLER_RABIN_ROUNDS} independent Miller-Rabin rounds against
 * `candidate`, with every witness drawn from `stream`. Matches
 * RSA4096/millerrabin.go's IsProbablyPrime exactly, including the
 * early-exit-on-proof-of-compositeness behavior.
 *
 * Precondition: candidate must be odd and > 3 (always true for anything
 * that came out of generateCandidate).
 */
export function isProbablyPrime(candidate: bigint, stream: Blake3XofStream): boolean {
  const nMinus1 = candidate - 1n;

  // Factor nMinus1 = 2^k * m, with m odd.
  let k = 0;
  let m = nMinus1;
  while ((m & 1n) === 0n) {
    m >>= 1n;
    k++;
  }

  const nMinus3 = candidate - 3n;

  for (let round = 0; round < MILLER_RABIN_ROUNDS; round++) {
    const a = generateWitness(stream, nMinus3);
    let x = modPow(a, m, candidate);

    if (x === 1n || x === nMinus1) {
      continue; // this round found no evidence of compositeness
    }

    let composite = true;
    for (let j = 0; j < k - 1; j++) {
      x = (x * x) % candidate;
      if (x === nMinus1) {
        composite = false;
        break;
      }
      if (x === 1n) {
        // Nontrivial square root of 1 -- mathematical proof of
        // compositeness, no need to check further.
        return false;
      }
    }
    if (composite) {
      return false;
    }
  }

  return true;
}
