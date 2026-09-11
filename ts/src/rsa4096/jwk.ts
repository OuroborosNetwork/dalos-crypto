/**
 * Encodes an assembled key as a canonical Arweave JWK, and derives the
 * Arweave address from it -- exactly matching the real
 * arweave-core/src/keys/{address,keyfile}.ts logic (read from
 * AncientPantheon/constructors/Codex/packages/arweave-core during the
 * original research session): kty="RSA", e="AQAB", n decodes to exactly
 * 512 bytes, address = Base64URL(SHA-256(n)). Direct port of
 * RSA4096/jwk.go.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bigIntToBytes } from './bigint-math.js';
import type { RSAKey } from './keyassembly.js';

/** Canonical 4096-bit modulus length in bytes. Matches RSA4096/jwk.go. */
export const ARWEAVE_MODULUS_BYTES = 512;

/** The canonical 9-field Arweave keyfile shape. Matches RSA4096/jwk.go's JWK. */
export interface JWK {
  kty: string;
  n: string;
  e: string;
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
}

/** Unpadded base64url encoding, matching RFC 7518 (JWK) integer encoding. */
function base64url(bytes: Uint8Array): string {
  let base64: string;
  if (typeof Buffer !== 'undefined') {
    base64 = Buffer.from(bytes).toString('base64');
  } else {
    base64 = btoa(String.fromCharCode(...bytes));
  }
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Encodes `key` as a canonical Arweave JWK. `n` is required to decode to
 * exactly {@link ARWEAVE_MODULUS_BYTES} bytes (guaranteed by construction
 * -- see RSA4096/jwk.go's ToJWK for the arithmetic proof, mirrored here).
 * Matches RSA4096/jwk.go's ToJWK exactly.
 */
export function toJWK(key: RSAKey): JWK {
  const nBytes = bigIntToBytes(key.n);
  if (nBytes.length !== ARWEAVE_MODULUS_BYTES) {
    throw new Error('toJWK: n is not exactly 512 bytes -- bit-fixing invariant violated upstream');
  }

  return {
    kty: 'RSA',
    n: base64url(nBytes),
    e: base64url(bigIntToBytes(key.e)),
    d: base64url(bigIntToBytes(key.d)),
    p: base64url(bigIntToBytes(key.p)),
    q: base64url(bigIntToBytes(key.q)),
    dp: base64url(bigIntToBytes(key.dp)),
    dq: base64url(bigIntToBytes(key.dq)),
    qi: base64url(bigIntToBytes(key.qi)),
  };
}

/**
 * Derives the Arweave address Base64URL(SHA-256(n)) directly from the
 * modulus, matching arweave-core's addressOf() exactly. Independently
 * re-validates n's decoded length itself (self-contained, doesn't depend
 * on toJWK having run first). Matches RSA4096/jwk.go's AddressOf exactly.
 */
export function addressOf(n: bigint): string {
  const nBytes = bigIntToBytes(n);
  if (nBytes.length !== ARWEAVE_MODULUS_BYTES) {
    throw new Error('addressOf: n is not exactly 512 bytes');
  }
  return base64url(sha256(nBytes));
}
