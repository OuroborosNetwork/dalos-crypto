/**
 * Wires the seed -> RSA-4096 JWK pipeline together, plus a self-contained
 * "textbook RSA" correctness check independent of any external library.
 * Direct port of RSA4096/pipeline.go.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { modPow } from './bigint-math.js';
import { type JWK, addressOf, toJWK } from './jwk.js';
import { type RSAKey, assembleKey } from './keyassembly.js';
import { findTwoPrimes, findTwoPrimesAsync } from './primesearch.js';
import type { ProgressCallback } from './progress.js';
import { newSeedStream } from './stream.js';

/** Bundles everything produced by one full run of the pipeline. */
export interface KeyGenResult {
  seed: string;
  p: bigint;
  q: bigint;
  key: RSAKey;
  jwk: JWK;
  address: string;
  pAttempts: number;
  qAttempts: number;
}

/**
 * Runs the complete seed -> RSA-4096 JWK pipeline: open the seed stream,
 * find two validated primes, assemble the key, encode the JWK, derive the
 * address. Matches RSA4096/pipeline.go's GenerateFromBitString exactly.
 *
 * `onProgress` is optional and purely observational (see progress.ts) --
 * a caller building a UI progress bar passes a callback here. Every
 * existing test and tool that omits it gets byte-for-byte identical
 * output to before progress reporting existed.
 *
 * This is the SYNCHRONOUS variant: it blocks the calling thread for the
 * full multi-second search. In a browser, that means the UI thread (and
 * therefore any progress bar built from `onProgress`) will NOT repaint
 * during the search -- use {@link generateFromBitStringAsync} instead for
 * an actual live-updating browser progress bar. This variant remains the
 * right default for Node/server contexts where blocking is acceptable
 * (same tradeoff already documented for `scalarMultiplier` vs
 * `scalarMultiplierAsync` in gen1/scalar-mult.ts).
 */
export function generateFromBitString(
  seedBitString: string,
  onProgress?: ProgressCallback,
): KeyGenResult {
  const stream = newSeedStream(seedBitString);
  const { p, q, pAttempts, qAttempts } = findTwoPrimes(stream, onProgress);
  const key = assembleKey(p, q);
  const jwk = toJWK(key);
  const address = addressOf(key.n);

  return { seed: seedBitString, p, q, key, jwk, address, pAttempts, qAttempts };
}

/**
 * Async variant of {@link generateFromBitString}, built on
 * {@link findTwoPrimesAsync}: yields to the event loop every 8 candidate
 * draws (see primesearch.ts), so a browser UI thread stays responsive and
 * an `onProgress` callback can actually drive a repainting progress bar
 * for the full duration of the search -- this is the recommended entry
 * point for any UI use of this package.
 */
export async function generateFromBitStringAsync(
  seedBitString: string,
  onProgress?: ProgressCallback,
): Promise<KeyGenResult> {
  const stream = newSeedStream(seedBitString);
  const { p, q, pAttempts, qAttempts } = await findTwoPrimesAsync(stream, onProgress);
  const key = assembleKey(p, q);
  const jwk = toJWK(key);
  const address = addressOf(key.n);

  return { seed: seedBitString, p, q, key, jwk, address, pAttempts, qAttempts };
}

/**
 * Verifies that `d` is genuinely the correct private exponent for (n, e)
 * by round-tripping several test messages through raw (unpadded) RSA:
 * c = m^e mod n, m' = c^d mod n, and checking m' === m -- deliberately
 * independent of any padding scheme (RSA-PSS, PKCS#1 v1.5, etc.). Matches
 * RSA4096/pipeline.go's SelfCheckTextbookRSA exactly.
 */
export function selfCheckTextbookRSA(key: RSAKey): void {
  const testMessages = [2n, 3n, 1234567n, 987654321n];
  for (const m of testMessages) {
    if (m >= key.n) {
      throw new Error('selfCheckTextbookRSA: test message >= n, test is malformed');
    }

    const c = modPow(m, key.e, key.n); // encrypt: c = m^e mod n
    const mPrime = modPow(c, key.d, key.n); // decrypt: m' = c^d mod n
    if (mPrime !== m) {
      throw new Error(
        `selfCheckTextbookRSA: round-trip FAILED for message ${m} -- d is not the correct inverse of e`,
      );
    }

    // Sign/verify direction (sign with d, verify with e) -- for RSA these
    // are the same operation mathematically, but worth checking
    // explicitly since it's the operation actually used for Arweave
    // transaction signing.
    const s = modPow(m, key.d, key.n);
    const mFromSig = modPow(s, key.e, key.n);
    if (mFromSig !== m) {
      throw new Error(`selfCheckTextbookRSA: sign/verify round-trip FAILED for message ${m}`);
    }
  }
}
