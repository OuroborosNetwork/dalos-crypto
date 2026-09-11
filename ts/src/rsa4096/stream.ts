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

/** Matches RSA4096/stream.go's seedBitStringLen (DALOS Genesis safe-scalar size). */
export const SEED_BIT_STRING_LEN = 1600;

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
 * Validates that `s` is exactly {@link SEED_BIT_STRING_LEN} characters of
 * '0'/'1'. Matches RSA4096/stream.go's validateSeedBitString.
 */
export function validateSeedBitString(s: string): void {
  if (s.length !== SEED_BIT_STRING_LEN) {
    throw new Error('seed bitstring must be exactly 1600 characters');
  }
  for (const c of s) {
    if (c !== '0' && c !== '1') {
      throw new Error("seed bitstring must contain only '0' and '1' characters");
    }
  }
}

/**
 * Takes the raw DALOS 1600-bit seed bitstring and returns a
 * {@link Blake3XofStream} that produces an effectively endless, fully
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
