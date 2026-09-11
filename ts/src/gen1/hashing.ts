/**
 * DALOS hashing, address encoding, and public-key string format.
 *
 * Ports the address-derivation pipeline from `Elliptic/KeyGeneration.go`
 * line-for-line:
 *
 *   seed-words / public-key-integer
 *          │
 *          ▼  UTF-8 encode   (Go's []byte(string))
 *          ▼  seven-fold Blake3 with specific output size
 *          │        (200 bytes for bit-string, 160 bytes for address)
 *          ▼  convertHashToBitString (for bitstring path)
 *                OR
 *          ▼  convertToLetters via 16×16 CHARACTER_MATRIX (for address path)
 *          │
 *          ▼  output
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { sevenFoldBlake3 } from '../dalos-blake3/index.js';
import {
  CHARACTER_MATRIX_FLAT,
  SMART_ACCOUNT_PREFIX,
  STANDARD_ACCOUNT_PREFIX,
} from './character-matrix.js';
import type { CoordAffine } from './coords.js';
import { DALOS_ELLIPSE, type Ellipse } from './curve.js';
import {
  BASE49_ALPHABET,
  bigIntToBase49,
  digitValueBase49,
  isValidBase49Char,
} from './scalar-mult.js';

// ============================================================================
// Utilities
// ============================================================================

/**
 * UTF-8 encode a string to a Uint8Array. Matches Go's `[]byte(string)`
 * which also uses UTF-8.
 */
const utf8 = new TextEncoder();
export function toUtf8Bytes(s: string): Uint8Array {
  return utf8.encode(s);
}

// ============================================================================
// Seed-word validation — the ONE contract, mirrored byte-for-byte from
// Elliptic/SeedWordsValidation.go
// ============================================================================

/** Fewest words a seed phrase may contain. */
export const MIN_SEED_WORDS = 1;
/** Most words a seed phrase may contain. */
export const MAX_SEED_WORDS = 256;
/** Fewest glyphs a single seed word may contain. */
export const MIN_SEED_WORD_GLYPHS = 1;
/** Most glyphs a single seed word may contain. */
export const MAX_SEED_WORD_GLYPHS = 256;

/** O(1) membership set built once from the 256-glyph DALOS alphabet. */
const CHARACTER_SET: ReadonlySet<string> = new Set(CHARACTER_MATRIX_FLAT);

/**
 * Thrown by `validateSeedWords` (and therefore by `seedWordsToBitString`/
 * `fromSeedWords`) when seed-word input violates the DALOS contract:
 * 1-256 words, each 1-256 glyphs, every glyph one of the 256 in the
 * DALOS character set.
 */
export class InvalidSeedWordsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidSeedWordsError';
  }
}

/**
 * The single, canonical seed-word input gate — mirrors Go's
 * `Elliptic.ValidateSeedWords` glyph-for-glyph. Final restriction level
 * (settled 2026-09-11): 1-256 words, each 1-256 glyphs (counted as
 * Unicode code points via `Array.from`, matching Go's `utf8.RuneCount-
 * InString`, not UTF-16 code units), every glyph one of the 256 glyphs
 * in the DALOS CharacterMatrix — a curated address-rendering alphabet,
 * not "any UTF-8 character". Within that range, word CHOICE is entirely
 * the caller's own responsibility.
 *
 * Called automatically by `seedWordsToBitString` (and therefore by
 * `fromSeedWords` and every registry primitive's `generateFromSeedWords`)
 * — every production entry point goes through here, so this is
 * impossible to bypass from a real caller.
 */
export function validateSeedWords(seedWords: readonly string[]): void {
  if (seedWords.length < MIN_SEED_WORDS || seedWords.length > MAX_SEED_WORDS) {
    throw new InvalidSeedWordsError(
      `seed words: expected between ${MIN_SEED_WORDS} and ${MAX_SEED_WORDS} words, got ${seedWords.length}`,
    );
  }
  for (let i = 0; i < seedWords.length; i++) {
    const word = seedWords[i] ?? '';
    const glyphs = Array.from(word);
    if (glyphs.length < MIN_SEED_WORD_GLYPHS || glyphs.length > MAX_SEED_WORD_GLYPHS) {
      throw new InvalidSeedWordsError(
        `seed word ${i} (${JSON.stringify(word)}): expected between ${MIN_SEED_WORD_GLYPHS} and ${MAX_SEED_WORD_GLYPHS} glyphs, got ${glyphs.length}`,
      );
    }
    for (const glyph of glyphs) {
      if (!CHARACTER_SET.has(glyph)) {
        throw new InvalidSeedWordsError(
          `seed word ${i} (${JSON.stringify(word)}): character ${JSON.stringify(glyph)} is not one of the 256 glyphs in the DALOS character set`,
        );
      }
    }
  }
}

/**
 * Parse a string of digits in the given base (10 or 49) to a bigint.
 *
 * For base 10 this is a simple `BigInt(s)` call. For base 49 we walk
 * the string character-by-character, mapping via `digitValueBase49`
 * and accumulating.
 */
export function parseBigIntInBase(s: string, base: 10 | 49): bigint {
  if (base === 10) {
    if (!/^\d+$/.test(s)) {
      throw new Error(`parseBigIntInBase: invalid base-10 string "${s}"`);
    }
    return BigInt(s);
  }
  // base 49
  // REQ-21 (F-BUG-004): match Go's big.Int.SetString all-or-nothing
  // semantics. Reject mixed-validity inputs at first invalid char
  // instead of silently accumulating as digit 0.
  for (const ch of s) {
    if (!isValidBase49Char(ch)) {
      throw new Error(`parseBigIntInBase: invalid base-49 character '${ch}'`);
    }
  }
  let result = 0n;
  for (const ch of s) {
    const v = digitValueBase49(ch);
    result = result * 49n + BigInt(v);
  }
  return result;
}

// ============================================================================
// Bit-string derivation (seed words, generic hashes)
// ============================================================================

/**
 * Derive a 1600-bit bitstring from a list of seed words.
 *
 * Pipeline (matches Go's `(*Ellipse).SeedWordsToBitString`):
 *   1. Join words with a single space
 *   2. UTF-8 encode to bytes
 *   3. Apply seven-fold Blake3 with output size S/8 = 200 bytes
 *   4. Interpret the 200-byte output as a big-endian bigint
 *   5. Render in base 2, left-pad with zeros to length S = 1600
 */
export function seedWordsToBitString(
  seedWords: readonly string[],
  e: Ellipse = DALOS_ELLIPSE,
): string {
  validateSeedWords(seedWords);
  const joined = seedWords.join(' ');
  const bytes = toUtf8Bytes(joined);
  // Byte-align the hash output size. DALOS has s=1600 → 200 bytes
  // exactly (back-compat preserved). Historical curves with
  // non-byte-aligned safe-scalars (LETO s=545, ARTEMIS s=1023) round up
  // to the next whole byte; the extra bits are discarded by
  // `convertHashToBitString(digest, e.s)` which truncates / left-pads
  // to exactly `e.s` chars.
  const outputSize = Math.ceil(e.s / 8);
  const digest = sevenFoldBlake3(bytes, outputSize);
  return convertHashToBitString(digest, e.s);
}

/**
 * Convert a hash byte-slice into a bit-string padded to `bitLength`
 * characters.
 *
 * Matches Go's `(*Ellipse).ConvertHashToBitString`:
 *   1. bytes → hex string
 *   2. hex → bigint (base 16)
 *   3. bigint → binary string (leading zeros stripped by big.Int.Text(2))
 *   4. left-pad with '0' to exactly `bitLength` characters
 */
export function convertHashToBitString(hash: Uint8Array, bitLength: number): string {
  // Build the full big-endian bit-string from bytes — each byte
  // contributes exactly 8 characters, no leading-zero stripping. This
  // produces identical output to the old `n.toString(2) + leftPad` path
  // for DALOS (where `hash.length * 8 === bitLength` exactly), so
  // byte-identity against the Go reference is preserved.
  //
  // F-MED-010 (v4.0.2): pre-v4.0.2 the loop body was `full += b.to-
  // String(2).padStart(8, '0')`. JS strings are immutable; `+=` in a
  // loop builds an O(n²) chain of intermediate concatenations under
  // most engines (V8 ropes some, but the optimisation is fragile).
  // The TS port already follows the `Array.push + join` pattern in
  // `bigIntToBase49` (REQ-29) for the same reason; mirrored here for
  // consistency. Output is byte-identical to the old `+=` path —
  // `parts.join('')` produces the same string, just in O(n).
  //
  // F-MED-010 follow-up (v4.0.2 publish recovery): switched from
  // `for (let i = 0; ...) parts[i] = hash[i].toString(...)` to
  // `Array.from(hash, ...)`. The indexed-access form tripped TS's
  // `noUncheckedIndexedAccess: true` rule (hash[i] types as `number |
  // undefined` even though the loop bound proves it's defined).
  // `Array.from(Uint8Array, mapper)` types `b` as `number` cleanly
  // with no non-null assertion needed. Output and big-O cost
  // unchanged.
  const parts = Array.from(hash, (b) => b.toString(2).padStart(8, '0'));
  const full = parts.join('');
  if (full.length === bitLength) return full;
  if (full.length > bitLength) {
    // Take the high-order `bitLength` bits — conventional when
    // extracting N bits from a Blake3 XOF output of N+ bits. Used by
    // the historical curves (LETO s=545, ARTEMIS s=1023) where
    // `Math.ceil(e.s / 8)` rounds up to the next whole byte and we
    // discard the surplus low bits here.
    return full.slice(0, bitLength);
  }
  // full.length < bitLength — left-pad with zeros.
  return '0'.repeat(bitLength - full.length) + full;
}

// ============================================================================
// Public-key string format
// ============================================================================

/**
 * Encode an affine point as a DALOS public-key string.
 *
 * Format: `"{prefixLenBase49}.{xyBase49}"`
 *   - `prefixLenBase49` — length of X's base-10 representation, in base 49
 *   - `xyBase49`        — concatenation of X and Y base-10 strings, parsed
 *                         as a base-10 bigint, re-rendered in base 49
 *
 * Matches Go's `AffineToPublicKey`.
 */
export function affineToPublicKey(input: CoordAffine): string {
  const xString = input.ax.toString(10);
  const yString = input.ay.toString(10);
  const xStringLength = BigInt(xString.length);
  const publicKeyPrefix = bigIntToBase49(xStringLength);
  const xyString = xString + yString;
  const publicKeyInteger = BigInt(xyString);
  const publicKey = bigIntToBase49(publicKeyInteger);
  return `${publicKeyPrefix}.${publicKey}`;
}

/**
 * Reverse of `affineToPublicKey`.
 *
 * Matches Go's `ConvertPublicKeyToAffineCoords`.
 * Throws on malformed input.
 */
export function publicKeyToAffineCoords(publicKey: string): CoordAffine {
  const parts = publicKey.split('.');
  if (parts.length !== 2) {
    // REQ-22 (F-BUG-005): distinguish missing-dot from extra-dot. The
    // previous unified "missing ." message was misleading for inputs like
    // "a.b.c". Mirrors the Go-side reject at Schnorr.go:131.
    throw new Error(
      `publicKeyToAffineCoords: invalid public key format: expected exactly 1 ".", got ${parts.length - 1}`,
    );
  }
  const prefix = parts[0];
  const body = parts[1];
  if (prefix === undefined || body === undefined) {
    throw new Error('publicKeyToAffineCoords: empty prefix or body');
  }

  const xLengthBig = parseBigIntInBase(prefix, 49);
  const xLength = Number(xLengthBig);
  if (!Number.isSafeInteger(xLength) || xLength < 1) {
    throw new Error(`publicKeyToAffineCoords: invalid X-length prefix ${xLengthBig}`);
  }

  const totalValue = parseBigIntInBase(body, 49);
  const totalValueStr = totalValue.toString(10);
  if (totalValueStr.length < xLength) {
    throw new Error('publicKeyToAffineCoords: body shorter than claimed X-length');
  }

  const xStr = totalValueStr.slice(0, xLength);
  const yStr = totalValueStr.slice(xLength);
  if (yStr.length === 0) {
    throw new Error('publicKeyToAffineCoords: Y component missing');
  }

  return { ax: BigInt(xStr), ay: BigInt(yStr) };
}

// ============================================================================
// Address derivation
// ============================================================================

/**
 * Derive the 160-character address body from a public-key integer.
 *
 * Pipeline (matches Go's `DalosAddressComputer`):
 *   1. publicKeyInt.toString(10) → bytes (UTF-8, which is ASCII here)
 *   2. Seven-fold Blake3 with output size = 160 bytes
 *   3. For each byte b: look up `CHARACTER_MATRIX[b/16][b%16]`
 *   4. Concatenate → 160-character string
 */
export function dalosAddressComputer(publicKeyInt: bigint): string {
  const decimalBytes = toUtf8Bytes(publicKeyInt.toString(10));
  const digest = sevenFoldBlake3(decimalBytes, 160);
  return convertToLetters(digest);
}

/**
 * Map each byte of `hash` through the 16×16 character matrix and
 * concatenate. Matches Go's `ConvertToLetters`.
 *
 * The output has exactly `hash.length` characters (each byte produces
 * one Unicode rune from the matrix).
 */
export function convertToLetters(hash: Uint8Array): string {
  let out = '';
  for (const b of hash) {
    out += CHARACTER_MATRIX_FLAT[b] ?? '';
  }
  return out;
}

/**
 * Compute the 160-character address body for a public-key string.
 *
 * 1. Strip the `{prefixLen}.` prefix
 * 2. Parse the base-49 body to a bigint
 * 3. `dalosAddressComputer` on that bigint
 *
 * Matches Go's `PublicKeyToAddress`.
 */
export function publicKeyToAddress(publicKey: string): string {
  const parts = publicKey.split('.');
  if (parts.length !== 2) {
    throw new Error('publicKeyToAddress: invalid format (missing ".")');
  }
  const body = parts[1];
  if (body === undefined) {
    throw new Error('publicKeyToAddress: empty body');
  }
  const publicKeyInt = parseBigIntInBase(body, 49);
  return dalosAddressComputer(publicKeyInt);
}

/**
 * Prefix pair used by a cryptographic primitive to brand its addresses.
 *
 * Both characters **must come from the DALOS 256-rune character matrix**
 * (`CHARACTER_MATRIX_FLAT`) so they render natively through every
 * downstream tool. DalosGenesis uses `Ѻ` / `Σ`; historical curves each
 * reserve their own pair.
 */
export interface AddressPrefixPair {
  readonly standard: string;
  readonly smart: string;
}

/** DALOS Genesis — unchanged, from `character-matrix.ts`. */
export const DALOS_PREFIXES: AddressPrefixPair = {
  standard: STANDARD_ACCOUNT_PREFIX,
  smart: SMART_ACCOUNT_PREFIX,
};

/**
 * Compose a full Ouronet-style account address from a public-key string.
 *
 * - `isSmart = true`   → `"<smartPrefix>." + address-body`
 * - `isSmart = false`  → `"<standardPrefix>." + address-body`
 *
 * Default prefixes are DALOS Genesis (`Ѻ` / `Σ`). Other primitives
 * (LETO / ARTEMIS / APOLLO historical curves, or any future Gen-N)
 * pass their own `prefixes` so the resulting address string uniquely
 * identifies the primitive that minted it. The 160-character body is
 * derived identically for all curves (seven-fold Blake3 over the
 * public-key integer, mapped through the 16×16 character matrix).
 *
 * Matches Go's `DalosAddressMaker` when called with default prefixes.
 */
export function dalosAddressMaker(
  publicKey: string,
  isSmart: boolean,
  prefixes: AddressPrefixPair = DALOS_PREFIXES,
): string {
  const body = publicKeyToAddress(publicKey);
  const prefix = isSmart ? prefixes.smart : prefixes.standard;
  return `${prefix}.${body}`;
}

// Re-export alphabet for discoverability from the hashing entry point
export { BASE49_ALPHABET };
