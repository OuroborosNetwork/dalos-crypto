/**
 * Stream bytes -> bit-fixed primality-test candidate. Direct port of
 * RSA4096/candidate.go -- see that file's doc comment for the full
 * reasoning behind each bit-fix.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import type { Blake3XofStream } from '../dalos-blake3/index.js';
import { bytesToBigInt } from './bigint-math.js';

/** Target size of one RSA-4096 prime factor. Matches RSA4096/candidate.go. */
export const CANDIDATE_BITS = 2048;
export const CANDIDATE_BYTES = CANDIDATE_BITS / 8; // 256

/**
 * Pulls exactly one fresh 2048-bit (256-byte) block off `stream` and
 * bit-fixes it into a legitimate primality-test candidate: top two bits
 * forced to 1 (guarantees exactly 2048 bits, and that two such primes
 * multiply to exactly 4096 bits), bottom bit forced to 1 (odd). Matches
 * RSA4096/candidate.go's GenerateCandidate exactly.
 */
export function generateCandidate(stream: Blake3XofStream): bigint {
  const buf = stream.read(CANDIDATE_BYTES);

  // Big-endian byte order: buf[0] is the most-significant byte. Both
  // indices are always in-bounds -- stream.read(CANDIDATE_BYTES) is
  // contractually guaranteed to return exactly CANDIDATE_BYTES bytes.
  buf[0] = buf[0]! | 0b1100_0000; // top two bits -> 1
  buf[CANDIDATE_BYTES - 1] = buf[CANDIDATE_BYTES - 1]! | 0b0000_0001; // bottom bit -> 1

  return bytesToBigInt(buf);
}
