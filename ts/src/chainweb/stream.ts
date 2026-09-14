/**
 * Seed(+index) -> deterministic 32-byte Ed25519 seed material, mirroring
 * `Chainweb/stream.go` exactly. See that file's doc comment for the full
 * design reasoning; this is a direct port, not a reinterpretation.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { type Blake3XofStream, createBlake3XofStream } from '../dalos-blake3/index.js';

/** Matches Chainweb/stream.go's chainwebStreamDomainTag exactly. */
const CHAINWEB_STREAM_DOMAIN_TAG = 'DALOS-gen1/ChainwebEd25519Stream/v1';

/**
 * A closed allow-list, NOT a floor -- matches Chainweb/stream.go's
 * allowedSeedBitStringLengths exactly (itself matching RSA4096/stream.go's
 * identical gate, for the identical reason -- see that file's comment).
 */
export const ALLOWED_SEED_BIT_STRING_LENGTHS: ReadonlySet<number> = new Set([
  1024, // APOLLO
  1600, // DALOS Genesis
]);

const textEncoder = new TextEncoder();

/** 4-byte big-endian length prefix followed by the data itself -- matches
 * Chainweb/stream.go's writeLenPrefixed exactly. */
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

/** Matches Chainweb/stream.go's validateSeedBitString exactly. */
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
 * Takes a raw seed bitstring plus a position index, and returns a
 * {@link Blake3XofStream} unique to that (seed, index) pair -- matches
 * Chainweb/stream.go's newSeedStream exactly: same domain tag, same
 * length-prefixed framing (tag, then seed, then 4-byte big-endian index),
 * same "hash the literal ASCII bytes of the bitstring" encoding choice.
 *
 * Every index, including 0, goes through this one uniform formula -- no
 * RSA4096-style index-0 special case, since this is a brand-new primitive
 * with no prior published output to preserve byte-identically. See the Go
 * file's doc comment for the full reasoning.
 */
export function newSeedStream(seedBitString: string, index: number): Blake3XofStream {
  validateSeedBitString(seedBitString);
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
    throw new Error('index must be a uint32 (0 .. 4294967295)');
  }

  const parts: Uint8Array[] = [];
  writeLenPrefixed(parts, textEncoder.encode(CHAINWEB_STREAM_DOMAIN_TAG));
  writeLenPrefixed(parts, textEncoder.encode(seedBitString));

  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false); // big-endian
  writeLenPrefixed(parts, indexBytes);

  return createBlake3XofStream(concatBytes(parts));
}
