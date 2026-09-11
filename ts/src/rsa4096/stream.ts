/**
 * Seed -> deterministic byte stream, mirroring `RSA4096/stream.go` exactly.
 * See that file's doc comment (and /.docs/deterministic-rsa4096-from-seed.md
 * §8.3/§9) for the full design reasoning; this is a direct port, not a
 * reinterpretation.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { type Blake3XofStream, createBlake3XofStream } from '../dalos-blake3/index.js';

/** Matches RSA4096/stream.go's rsa4096StreamDomainTag exactly. */
const RSA4096_STREAM_DOMAIN_TAG = 'DALOS-gen1/RSA4096Stream/v1';

/**
 * A sanity floor, NOT a cryptographic requirement of this construction --
 * matches RSA4096/stream.go's minSeedBitStringLen exactly. Blake3-XOF
 * hashes an input of any length correctly; this package was originally
 * written for DALOS Genesis's 1600-bit seed only, but the same pipeline
 * works unchanged for any of DALOS_Crypto's other curve safe-scalar
 * sizes -- e.g. APOLLO's 1024 bits -- since the seed is just bytes to a
 * hash function, not something this construction interprets
 * structurally. 128 is chosen only to catch obvious mistakes, not as a
 * security boundary; it sits comfortably below every real curve this
 * repo defines (LETO's 545 is the smallest).
 */
export const MIN_SEED_BIT_STRING_LEN = 128;

const textEncoder = new TextEncoder();

/**
 * 4-byte big-endian length prefix followed by the data itself -- matches
 * RSA4096/stream.go's writeLenPrefixed exactly (which itself matches
 * Elliptic/Schnorr.go's Schnorr-v2 framing convention).
 */
function writeLenPrefixed(parts: Uint8Array[], data: Uint8Array): void {
  const lenBytes = new Uint8Array(4);
  new DataView(lenBytes.buffer).setUint32(0, data.length, false); // big-endian
  parts.push(lenBytes, data);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Validates that `s` is at least {@link MIN_SEED_BIT_STRING_LEN}
 * characters of '0'/'1'. Matches RSA4096/stream.go's
 * validateSeedBitString exactly -- deliberately does NOT pin an exact
 * length, see MIN_SEED_BIT_STRING_LEN's doc comment.
 */
export function validateSeedBitString(s: string): void {
  if (s.length < MIN_SEED_BIT_STRING_LEN) {
    throw new Error('seed bitstring must be at least 128 characters');
  }
  for (const c of s) {
    if (c !== '0' && c !== '1') {
      throw new Error("seed bitstring must contain only '0' and '1' characters");
    }
  }
}

/**
 * Takes a raw pre-EC-clamping seed bitstring -- for WHICHEVER curve
 * produced it (DALOS Genesis's 1600 bits, APOLLO's 1024, or any other
 * curve's safe-scalar size -- see MIN_SEED_BIT_STRING_LEN) -- and returns
 * a {@link Blake3XofStream} that produces an effectively endless, fully
 * deterministic stream of pseudorandom-looking bytes derived from it.
 * Matches RSA4096/stream.go's NewSeedStream exactly: same domain tag, same
 * length-prefixed framing, same "hash the literal ASCII bytes of the
 * bitstring" encoding choice (not bit-packed -- see the Go doc comment for
 * why: it removes an entire class of MSB/LSB-ordering cross-language bugs).
 */
export function newSeedStream(seedBitString: string): Blake3XofStream {
  validateSeedBitString(seedBitString);

  const parts: Uint8Array[] = [];
  writeLenPrefixed(parts, textEncoder.encode(RSA4096_STREAM_DOMAIN_TAG));
  writeLenPrefixed(parts, textEncoder.encode(seedBitString));

  return createBlake3XofStream(concatBytes(parts));
}
