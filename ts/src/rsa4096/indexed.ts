/**
 * Deterministic index-based derivation of MULTIPLE independent RSA-4096
 * keypairs (and therefore Arweave addresses) from the SAME seed
 * bitstring. Direct port of RSA4096/indexed.go -- see that file's doc
 * comment for the full design reasoning; this is a port, not a
 * reinterpretation.
 *
 * Motivation (settled 2026-09-11): a seed phrase's whole point is to be
 * able to derive many usable accounts, not just one -- but RSA has no
 * additive-homomorphism trick the way EC scalars do, so there is no
 * BIP-32-style non-hardened derivation to borrow. Every "child" RSA-4096
 * key really is an independent full keypair, run through the entire
 * prime search again -- the derivation only has to produce a fresh,
 * independent, deterministic SEED per index; the expensive part
 * (generateFromBitString/generateFromBitStringAsync) is reused completely
 * unchanged.
 *
 * Deliberately scoped to the RSA/Arweave layer ONLY -- the DALOS/APOLLO
 * EC account that produced the input seedBitString is untouched by this
 * file: one Ouronet EC account, many independent Arweave addresses under
 * it, not a full parallel HD tree.
 *
 * Backward compatibility is structural, not just tested: index 0 is
 * special-cased to call generateFromBitString/generateFromBitStringAsync
 * directly on the unmodified seedBitString, so "address #0" is
 * byte-identical, forever, to every already-published, already-frozen
 * result -- this file adds a capability, it cannot change any existing
 * output.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { blake3SumCustom } from '../dalos-blake3/index.js';
import {
  type KeyGenResult,
  generateFromBitString,
  generateFromBitStringAsync,
} from './pipeline.js';
import type { ProgressCallback } from './progress.js';
import { concatBytes, textEncoder, validateSeedBitString, writeLenPrefixed } from './stream.js';

/** Matches RSA4096/indexed.go's rsa4096IndexDomainTag exactly. */
const RSA4096_INDEX_DOMAIN_TAG = 'DALOS-gen1/RSA4096Index/v1';

/**
 * The largest index this API accepts, matching Go's `uint32` range
 * exactly (JS has no native unsigned-32-bit integer type, so this is
 * enforced explicitly rather than by the type system).
 */
export const MAX_INDEX = 0xffffffff;

/**
 * Renders `bytes` as a big-endian bitstring, 8 characters per byte, no
 * leading-zero stripping. Matches RSA4096/indexed.go's
 * hashBytesToBitString exactly. Deliberately simpler than
 * gen1/hashing.ts's convertHashToBitString (which also handles
 * non-byte-aligned bit lengths for LETO/ARTEMIS): every length
 * ALLOWED_SEED_BIT_STRING_LENGTHS permits (1024, 1600) is already an
 * exact multiple of 8, so there is no partial-byte case here. Kept local
 * to rsa4096/ rather than importing from gen1/, preserving this
 * package's existing zero-dependency-on-gen1 boundary.
 */
export function hashBytesToBitString(bytes: Uint8Array): string {
  let out = '';
  for (const byteVal of bytes) {
    for (let bit = 7; bit >= 0; bit--) {
      out += (byteVal >> bit) & 1 ? '1' : '0';
    }
  }
  return out;
}

/**
 * Encodes `index` as 4 big-endian bytes, matching Go's
 * `binary.BigEndian.PutUint32` exactly.
 */
function indexToBytes(index: number): Uint8Array {
  if (!Number.isInteger(index) || index < 0 || index > MAX_INDEX) {
    throw new Error(`index must be an integer in [0, ${MAX_INDEX}], got ${index}`);
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, index, false); // big-endian
  return bytes;
}

/**
 * Derives a fresh, independent seed bitstring of the SAME length as
 * `seedBitString` for a given index. Matches RSA4096/indexed.go's
 * deriveIndexedSeedBitString exactly: one domain-separated Blake3 hash
 * of (domain tag, the seed bitstring's literal UTF-8 bytes, a 4-byte
 * big-endian index), each length-prefixed exactly like stream.ts's own
 * newSeedStream framing, asked for exactly `seedBitString.length / 8`
 * bytes of output -- rendered 8 bits per byte, that automatically
 * produces a bitstring of exactly the same length as the input, so the
 * result satisfies {@link ALLOWED_SEED_BIT_STRING_LENGTHS} without that
 * gate ever needing to know indices exist.
 *
 * Deliberately NOT chained/sequential: index 1000000's derivation does
 * not depend on having derived any other index first -- every index is
 * a pure function of `(seedBitString, index)`.
 */
export function deriveIndexedSeedBitString(seedBitString: string, index: number): string {
  validateSeedBitString(seedBitString);

  const parts: Uint8Array[] = [];
  writeLenPrefixed(parts, textEncoder.encode(RSA4096_INDEX_DOMAIN_TAG));
  writeLenPrefixed(parts, textEncoder.encode(seedBitString));
  writeLenPrefixed(parts, indexToBytes(index));

  // Exact division is safe: ALLOWED_SEED_BIT_STRING_LENGTHS only permits
  // 1024 and 1600, both multiples of 8.
  const outputSize = seedBitString.length / 8;
  const digest = blake3SumCustom(concatBytes(parts), outputSize);

  return hashBytesToBitString(digest);
}

/**
 * Derives Arweave address #`index` from the same seed bitstring that
 * produces address #0 via {@link generateFromBitString} -- the same
 * seed, a multitude of independent addresses, any index directly
 * reachable without generating the ones before it.
 *
 * `index === 0` calls {@link generateFromBitString} directly on the
 * UNMODIFIED `seedBitString` -- byte-identical, forever, to every
 * already-published and already-frozen "address #0" result. Every other
 * index runs one extra domain-separated hash
 * ({@link deriveIndexedSeedBitString}) to derive a fresh, independent
 * seed of the same length, then the exact same, otherwise completely
 * unmodified, prime-search pipeline index 0 also uses.
 *
 * Synchronous -- see {@link generateFromBitStringAtIndexAsync} for the
 * event-loop-yielding variant a browser UI should use instead.
 */
export function generateFromBitStringAtIndex(
  seedBitString: string,
  index: number,
  onProgress?: ProgressCallback,
): KeyGenResult {
  if (index === 0) {
    return generateFromBitString(seedBitString, onProgress);
  }
  const indexedSeed = deriveIndexedSeedBitString(seedBitString, index);
  return generateFromBitString(indexedSeed, onProgress);
}

/**
 * Async variant of {@link generateFromBitStringAtIndex}, built on
 * {@link generateFromBitStringAsync} -- yields to the event loop during
 * the prime search so a browser UI thread stays responsive, exactly like
 * the unindexed async variant. This is the recommended entry point for
 * any UI that lets a user pick/reveal multiple Arweave addresses from one
 * seed.
 */
export async function generateFromBitStringAtIndexAsync(
  seedBitString: string,
  index: number,
  onProgress?: ProgressCallback,
): Promise<KeyGenResult> {
  if (index === 0) {
    return generateFromBitStringAsync(seedBitString, onProgress);
  }
  const indexedSeed = deriveIndexedSeedBitString(seedBitString, index);
  return generateFromBitStringAsync(indexedSeed, onProgress);
}
