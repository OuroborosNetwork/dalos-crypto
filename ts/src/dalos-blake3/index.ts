/**
 * @stoachain/dalos-blake3 (internal subpath — will be extracted to a
 * sibling npm package in Phase 11).
 *
 * Blake3 XOF wrapper matching the Go reference's
 * `Blake3.SumCustom(input, outputBytes)` interface byte-for-byte.
 * Uses `@noble/hashes/blake3` under the hood.
 *
 * Verified externally by the DALOS author: the Go Blake3
 * implementation in `StoaChain/Blake3` produces output byte-identical
 * to the Blake3 reference. `@noble/hashes/blake3` is also
 * spec-compliant (NIST SP 800-185 / BLAKE3 paper), independently
 * audited. Therefore outputs from this wrapper match Go bit-for-bit
 * for every input and output-length combination.
 *
 * Also exports the DALOS-specific `sevenFoldBlake3` — the repeated
 * application of Blake3 seven times that the DALOS address-derivation
 * pipeline uses.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { blake3 } from '@noble/hashes/blake3.js';

/**
 * Blake3 with custom output length.
 *
 * Matches Go's `Blake3.SumCustom(input []byte, outputBytes int) []byte`.
 * For input-length independence and any output length up to 2^64 bytes.
 *
 * @param input        — the data to hash
 * @param outputBytes  — the desired output length in bytes
 * @returns a fresh Uint8Array of exactly `outputBytes` bytes
 */
export function blake3SumCustom(input: Uint8Array, outputBytes: number): Uint8Array {
  if (!Number.isInteger(outputBytes) || outputBytes < 1) {
    throw new Error(`blake3SumCustom: outputBytes must be a positive integer, got ${outputBytes}`);
  }
  return blake3(input, { dkLen: outputBytes });
}

/**
 * Apply Blake3 seven times in sequence, feeding each round's output
 * into the next round's input. Every round produces `outputBytes`
 * of output.
 *
 * This is the construction used by the DALOS pipelines:
 *   - Seed-words → bit-string:  7-fold, outputBytes = S/8 = 200 (= 1600 bits)
 *   - Public-key-int → address: 7-fold, outputBytes = 160 (= 1280 bits)
 *
 * The extra rounds provide no cryptographic benefit beyond the first
 * (Blake3 is already PRF-secure in a single application), but they
 * are part of the frozen Genesis construction and must be preserved
 * byte-for-byte.
 *
 * @param input        — the seed data
 * @param outputBytes  — output length per round (and of final result)
 */
export function sevenFoldBlake3(input: Uint8Array, outputBytes: number): Uint8Array {
  let h: Uint8Array = blake3SumCustom(input, outputBytes);
  for (let i = 1; i < 7; i++) {
    h = blake3SumCustom(h, outputBytes);
  }
  return h;
}

/**
 * A continuing Blake3 XOF stream: seed it once with `input`, then call
 * `read(n)` as many times as needed to pull successive, non-overlapping
 * chunks of deterministic pseudorandom output -- matching the Go side's
 * `Blake3.Hasher.XOF()` (an `io.Reader`) exactly. Used by the RSA4096
 * package (`../rsa4096/`), which needs an unbounded, seekable-forward
 * stream to drive its prime search, not a single fixed-length digest.
 *
 * Verified this session: `@noble/hashes`'s `blake3.create().xof(n)` calls
 * continue squeezing from where the previous call left off (confirmed by
 * checking `_BLAKE3.writeInto`'s use of persistent instance state, and by
 * a smoke test showing two chunked `.xof(16)` calls concatenate to the
 * exact same bytes as one `blake3(input, {dkLen: 32})` call) -- so this is
 * a thin, honest wrapper, not new cryptographic logic.
 */
export interface Blake3XofStream {
  /** Returns the next `n` bytes of the stream. Never rewinds, never repeats. */
  read(n: number): Uint8Array;
}

/** Opens a new {@link Blake3XofStream} over `input` (unkeyed Blake3). */
export function createBlake3XofStream(input: Uint8Array): Blake3XofStream {
  const hasher = blake3.create({});
  hasher.update(input);
  return {
    read(n: number): Uint8Array {
      return hasher.xof(n);
    },
  };
}
