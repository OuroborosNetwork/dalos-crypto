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
 * A closed allow-list, NOT a floor -- matches RSA4096/stream.go's
 * allowedSeedBitStringLengths exactly. Earlier versions of this package
 * accepted any bitstring >= 128 characters (Blake3-XOF has no structural
 * opinion on input length, so that worked) -- but it left the door open
 * to an unbounded, unaudited "any string, any length" input path with no
 * real derivation story and no tie to any validated seed source.
 *
 * Settled 2026-09-11: RSA-4096's actual security comes from the 2048-bit
 * prime search space, not from seed length -- once the seed has enough
 * bits to unambiguously seed the Blake3-XOF stream (128 bits already
 * cleared that bar many times over), a longer seed buys zero additional
 * margin. So there is no reason to accept arbitrary lengths, and a real
 * reason not to: gating to EXACTLY the two lengths that come out of this
 * repo's two production EC curves -- APOLLO's 1024-bit safe scalar and
 * DALOS Genesis's 1600-bit safe scalar -- structurally forces every RSA
 * seed to have passed through one of those two curves' own
 * already-validated pipelines (seed-word charset/count checks, bitmap
 * dimensions, etc. -- see `ts/src/gen1/hashing.ts`'s `validateSeedWords`),
 * rather than accepting raw bytes that never went through any of that.
 */
export const ALLOWED_SEED_BIT_STRING_LENGTHS: ReadonlySet<number> = new Set([
  1024, // APOLLO
  1600, // DALOS Genesis
]);

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
 * Validates that `s` is exactly one of {@link ALLOWED_SEED_BIT_STRING_LENGTHS}
 * characters of '0'/'1' -- 1024 (APOLLO) or 1600 (DALOS Genesis), no other
 * length however long. Matches RSA4096/stream.go's validateSeedBitString
 * exactly.
 */
export function validateSeedBitString(s: string): void {
  if (!ALLOWED_SEED_BIT_STRING_LENGTHS.has(s.length)) {
    throw new Error(
      'seed bitstring must be exactly 1024 (APOLLO) or 1600 (DALOS Genesis) characters',
    );
  }
  for (const c of s) {
    if (c !== '0' && c !== '1') {
      throw new Error("seed bitstring must contain only '0' and '1' characters");
    }
  }
}

/**
 * Takes a raw pre-EC-clamping seed bitstring -- for EITHER of the two
 * curves this package accepts (DALOS Genesis's 1600 bits or APOLLO's
 * 1024 -- see ALLOWED_SEED_BIT_STRING_LENGTHS) -- and returns
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
