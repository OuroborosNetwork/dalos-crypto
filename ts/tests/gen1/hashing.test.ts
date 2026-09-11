/**
 * Phase 3 tests — hashing, address encoding, public-key format.
 *
 * This is the FIRST BYTE-IDENTITY GATE against the committed Go
 * test-vector corpus (`../testvectors/v1_genesis.json`). If any of
 * these tests fail, the port has diverged from Go at some pipeline
 * step and Phase 4 cannot proceed.
 *
 * Gates:
 *   1. seedWordsToBitString(words) must match `derived_bitstring`
 *      for all 15 seed-word vectors
 *   2. dalosAddressMaker(public_key, false) must match
 *      `standard_address` for all 105 vectors
 *   3. dalosAddressMaker(public_key, true) must match
 *      `smart_address` for all 105 vectors
 *   4. affineToPublicKey ∘ publicKeyToAffineCoords round-trip must
 *      preserve every public key in the corpus
 */

import { describe, expect, it } from 'vitest';
import {
  affineToPublicKey,
  convertHashToBitString,
  convertToLetters,
  dalosAddressComputer,
  dalosAddressMaker,
  InvalidSeedWordsError,
  MAX_SEED_WORD_GLYPHS,
  MAX_SEED_WORDS,
  MIN_SEED_WORD_GLYPHS,
  MIN_SEED_WORDS,
  parseBigIntInBase,
  publicKeyToAddress,
  publicKeyToAffineCoords,
  seedWordsToBitString,
  toUtf8Bytes,
  validateSeedWords,
} from '../../src/gen1/hashing.ts';
import { bitmapVectors, bitstringVectors, schnorrVectors, seedWordsVectors } from '../fixtures.ts';

// ============================================================================
// Utilities
// ============================================================================

describe('toUtf8Bytes', () => {
  it('encodes ASCII identity-style', () => {
    expect(toUtf8Bytes('abc')).toEqual(new Uint8Array([0x61, 0x62, 0x63]));
  });

  it('encodes Cyrillic correctly (2-byte UTF-8)', () => {
    // 'Ѻ' = U+047A → UTF-8 [0xD1, 0xBA]
    expect(toUtf8Bytes('Ѻ')).toEqual(new Uint8Array([0xd1, 0xba]));
  });

  it('encodes Greek correctly', () => {
    // 'Σ' = U+03A3 → UTF-8 [0xCE, 0xA3]
    expect(toUtf8Bytes('Σ')).toEqual(new Uint8Array([0xce, 0xa3]));
  });
});

describe('parseBigIntInBase', () => {
  it('base 10 basic cases', () => {
    expect(parseBigIntInBase('0', 10)).toBe(0n);
    expect(parseBigIntInBase('12345', 10)).toBe(12345n);
    expect(parseBigIntInBase('123456789012345678901234567890', 10)).toBe(
      123456789012345678901234567890n,
    );
  });

  it('base 10 rejects invalid', () => {
    expect(() => parseBigIntInBase('abc', 10)).toThrow();
    expect(() => parseBigIntInBase('12.5', 10)).toThrow();
  });

  it('base 49 digit values match BASE49_ALPHABET', () => {
    expect(parseBigIntInBase('0', 49)).toBe(0n);
    expect(parseBigIntInBase('9', 49)).toBe(9n);
    expect(parseBigIntInBase('a', 49)).toBe(10n);
    expect(parseBigIntInBase('M', 49)).toBe(48n);
    expect(parseBigIntInBase('10', 49)).toBe(49n);
    expect(parseBigIntInBase('MM', 49)).toBe(48n * 49n + 48n);
  });

  // REQ-21 (F-BUG-004): match Go's big.Int.SetString all-or-nothing semantics.
  // A single invalid base-49 character must cause an explicit throw rather than
  // silently accumulating as digit 0.
  it('REQ-21: throws on base-49 input containing punctuation (!@) with explicit char in message', () => {
    expect(() => parseBigIntInBase('123!@', 49)).toThrow(/invalid base-49 character '!'/);
  });

  it('REQ-21: throws on base-49 input containing uppercase past M (e.g., "N") with explicit char in message', () => {
    expect(() => parseBigIntInBase('123N', 49)).toThrow(/invalid base-49 character 'N'/);
  });
});

// ============================================================================
// convertHashToBitString
// ============================================================================

describe('convertHashToBitString', () => {
  it('handles a small hash correctly', () => {
    // 2 bytes [0b01010101, 0b10101010] = 0x55AA = 21930
    const hash = new Uint8Array([0x55, 0xaa]);
    // As 16-bit binary: "0101010110101010"
    expect(convertHashToBitString(hash, 16)).toBe('0101010110101010');
  });

  it('pads with leading zeros when bitLength > naturally produced bits', () => {
    const hash = new Uint8Array([0x01]);
    expect(convertHashToBitString(hash, 16)).toBe('0000000000000001');
  });

  it('zero hash maps to all zeros of requested length', () => {
    const hash = new Uint8Array([0, 0, 0]);
    expect(convertHashToBitString(hash, 24)).toBe('0'.repeat(24));
  });
});

// ============================================================================
// Public-key format round-trip
// ============================================================================

describe('publicKeyToAffineCoords + affineToPublicKey round-trip', () => {
  it('preserves every public key in the corpus (all 105 records)', () => {
    const allVectors = [
      ...bitstringVectors(),
      ...seedWordsVectors(),
      ...bitmapVectors(),
      ...schnorrVectors(),
    ];
    for (const v of allVectors) {
      const pk = v.public_key;
      const coords = publicKeyToAffineCoords(pk);
      const recoded = affineToPublicKey(coords);
      expect(recoded).toBe(pk);
    }
  });

  it('rejects malformed public keys', () => {
    expect(() => publicKeyToAffineCoords('no-dot-here')).toThrow();
    expect(() => publicKeyToAffineCoords('.')).toThrow();
  });

  // REQ-22 (TS portion): the EXTRA-DOT case must produce a clear error
  // identifying the actual problem (got 2 dots instead of 1), not the
  // misleading "missing ." message that hid the real issue.
  it('REQ-22: rejects extra-dot public keys with explicit count in message', () => {
    expect(() => publicKeyToAffineCoords('a.b.c')).toThrow(/expected exactly 1 ".", got 2/);
  });
});

// ============================================================================
// BYTE-IDENTITY GATE 1: seedWordsToBitString === Go's derived_bitstring
// ============================================================================

describe('seedWordsToBitString (BYTE-IDENTITY vs Go corpus)', () => {
  const vectors = seedWordsVectors();

  it('all 15 seed-words vectors produce byte-identical bitstrings', () => {
    for (const v of vectors) {
      const result = seedWordsToBitString(v.input_words);
      expect(result).toBe(v.derived_bitstring);
      expect(result).toHaveLength(1600); // DALOS_ELLIPSE.s
    }
  });

  it('Unicode seed words round-trip correctly (Cyrillic)', () => {
    const v = vectors.find((x) => x.input_words[0] === 'жизнь');
    expect(v).toBeDefined();
    expect(seedWordsToBitString(v!.input_words)).toBe(v!.derived_bitstring);
  });

  it('Unicode seed words round-trip correctly (Greek)', () => {
    const v = vectors.find((x) => x.input_words[0] === 'Δελτα');
    expect(v).toBeDefined();
    expect(seedWordsToBitString(v!.input_words)).toBe(v!.derived_bitstring);
  });

  it('Unicode seed words round-trip correctly (accented Latin)', () => {
    const v = vectors.find((x) => x.input_words[0] === 'café');
    expect(v).toBeDefined();
    expect(seedWordsToBitString(v!.input_words)).toBe(v!.derived_bitstring);
  });

  it('the prefix characters themselves as seed words work', () => {
    const v = vectors.find((x) => x.input_words[0] === 'Ѻ');
    expect(v).toBeDefined();
    expect(seedWordsToBitString(v!.input_words)).toBe(v!.derived_bitstring);
  });
});

// ============================================================================
// convertToLetters + dalosAddressComputer
// ============================================================================

describe('convertToLetters', () => {
  it('produces one character per input byte', () => {
    const hash = new Uint8Array([0, 1, 10, 100, 255]);
    const result = convertToLetters(hash);
    // The result is a 5-character string (each byte → one BMP char).
    // BMP chars occupy 1 UTF-16 code unit, so .length == 5.
    expect(result.length).toBe(5);
  });

  it('byte 10 maps to Ѻ (Cyrillic Round Omega)', () => {
    expect(convertToLetters(new Uint8Array([10]))).toBe('Ѻ');
  });

  it('byte 185 maps to Σ (Greek Capital Sigma)', () => {
    expect(convertToLetters(new Uint8Array([185]))).toBe('Σ');
  });

  it('byte 0 maps to "0"', () => {
    expect(convertToLetters(new Uint8Array([0]))).toBe('0');
  });
});

describe('dalosAddressComputer', () => {
  it('produces a 160-character address body for any public-key integer', () => {
    const body = dalosAddressComputer(12345n);
    // Length measured in code units; all chars are BMP so == number of chars.
    expect(body.length).toBe(160);
  });

  it('is deterministic', () => {
    const a = dalosAddressComputer(99999n);
    const b = dalosAddressComputer(99999n);
    expect(a).toBe(b);
  });
});

// ============================================================================
// BYTE-IDENTITY GATE 2: dalosAddressMaker === Go's standard/smart_address
// ============================================================================

// NOTE: Only 85 of the 105 vectors have address fields:
//   50 bitstring + 15 seed-words + 20 bitmap = 85
//   Schnorr vectors (20) only store priv/pub/msg/signature, not addresses.
describe('dalosAddressMaker — STANDARD addresses (BYTE-IDENTITY vs Go corpus)', () => {
  const all = [...bitstringVectors(), ...seedWordsVectors(), ...bitmapVectors()];

  it(`all ${all.length} address-bearing vectors produce byte-identical Ѻ. addresses`, () => {
    for (const v of all) {
      const result = dalosAddressMaker(v.public_key, false);
      expect(result).toBe(v.standard_address);
      // Every address starts with "Ѻ."
      expect(result.startsWith('Ѻ.')).toBe(true);
    }
  });
});

describe('dalosAddressMaker — SMART addresses (BYTE-IDENTITY vs Go corpus)', () => {
  const all = [...bitstringVectors(), ...seedWordsVectors(), ...bitmapVectors()];

  it(`all ${all.length} address-bearing vectors produce byte-identical Σ. addresses`, () => {
    for (const v of all) {
      const result = dalosAddressMaker(v.public_key, true);
      expect(result).toBe(v.smart_address);
      // Every address starts with "Σ."
      expect(result.startsWith('Σ.')).toBe(true);
    }
  });
});

describe('Schnorr-vector public keys produce valid addresses (round-trip sanity)', () => {
  // Schnorr vectors don't store expected addresses, but we can still
  // verify the derivation runs cleanly and produces the expected
  // prefix + length.
  const all = schnorrVectors();

  it('all 20 Schnorr-vector public keys produce well-formed addresses', () => {
    for (const v of all) {
      const std = dalosAddressMaker(v.public_key, false);
      const smart = dalosAddressMaker(v.public_key, true);
      expect(std.startsWith('Ѻ.')).toBe(true);
      expect(smart.startsWith('Σ.')).toBe(true);
      expect(std.slice(2)).toHaveLength(160);
      expect(smart.slice(2)).toHaveLength(160);
      // Both derivations produce the same body
      expect(std.slice(2)).toBe(smart.slice(2));
    }
  });
});

describe('publicKeyToAddress (body only, no prefix) — sanity', () => {
  it('matches the body portion of standard_address', () => {
    const all = [...bitstringVectors().slice(0, 5)];
    for (const v of all) {
      const body = publicKeyToAddress(v.public_key);
      // standard_address is "Ѻ." + body
      expect(v.standard_address.slice(2)).toBe(body);
    }
  });
});

// ============================================================================
// validateSeedWords — the final restriction level (settled 2026-09-11):
// 1-256 words, each 1-256 glyphs, every glyph in the 256-glyph DALOS
// character set. Mirrors Elliptic.ValidateSeedWords glyph-for-glyph.
// ============================================================================
describe('validateSeedWords / seedWordsToBitString input gate', () => {
  it('accepts the boundary minimum: 1 word, 1 glyph', () => {
    expect(() => validateSeedWords(['a'])).not.toThrow();
    expect(MIN_SEED_WORDS).toBe(1);
    expect(MIN_SEED_WORD_GLYPHS).toBe(1);
  });

  it('accepts the boundary maximum: 256 words, each 256 glyphs', () => {
    const words = Array.from({ length: MAX_SEED_WORDS }, () => 'a'.repeat(MAX_SEED_WORD_GLYPHS));
    expect(() => validateSeedWords(words)).not.toThrow();
  });

  it('rejects 0 words', () => {
    expect(() => validateSeedWords([])).toThrow(InvalidSeedWordsError);
  });

  it('rejects 257 words', () => {
    const words = Array.from({ length: MAX_SEED_WORDS + 1 }, () => 'a');
    expect(() => validateSeedWords(words)).toThrow(InvalidSeedWordsError);
  });

  it('rejects an empty-string word (0 glyphs)', () => {
    expect(() => validateSeedWords(['hello', ''])).toThrow(InvalidSeedWordsError);
  });

  it('rejects a word of 257 glyphs', () => {
    expect(() => validateSeedWords(['a'.repeat(MAX_SEED_WORD_GLYPHS + 1)])).toThrow(
      InvalidSeedWordsError,
    );
  });

  it('rejects a character outside the 256-glyph DALOS set (e.g. Chinese)', () => {
    expect(() => validateSeedWords(['中文'])).toThrow(InvalidSeedWordsError);
  });

  it('rejects a Cyrillic letter that is excluded from the matrix as a Latin homoglyph (е.g. а, е, о, р, с)', () => {
    // 'привет' contains р and е, both excluded from the DALOS Cyrillic
    // subset specifically because they're homoglyphs of Latin letters
    // already in the matrix (р looks like Latin p, е looks like Latin e).
    expect(() => validateSeedWords(['привет'])).toThrow(InvalidSeedWordsError);
  });

  it('rejects a Greek letter excluded as a Latin homoglyph (ο, υ) or an accented vowel (ά)', () => {
    expect(() => validateSeedWords(['κόσμε'])).toThrow(InvalidSeedWordsError);
  });

  it('accepts the in-charset Cyrillic/Greek replacements used by the frozen corpus', () => {
    expect(() => validateSeedWords(['жизнь', 'плющ'])).not.toThrow();
    expect(() => validateSeedWords(['Δελτα', 'Σιγμα', 'Ωμεγα'])).not.toThrow();
  });

  it('seedWordsToBitString throws the same InvalidSeedWordsError for bad input', () => {
    expect(() => seedWordsToBitString([])).toThrow(InvalidSeedWordsError);
    expect(() => seedWordsToBitString(['привет'])).toThrow(InvalidSeedWordsError);
  });
});
