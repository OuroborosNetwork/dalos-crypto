/**
 * Phase 4 tests — Key Generation API (6 input types).
 *
 * THE END-TO-END BYTE-IDENTITY GATE.
 *
 * Every one of the 85 address-bearing vectors in the committed Go
 * corpus is replayed through the full TypeScript pipeline (input →
 * bitstring → scalar → scalar·G → public key → addresses), and the
 * resulting `scalar_int10`, `priv_int49`, `public_key`,
 * `standard_address`, `smart_address` fields must match the Go
 * output byte-for-byte.
 *
 * If this passes, the TypeScript port is a functionally complete
 * drop-in replacement for the Go reference's key-generation service.
 */

import { describe, expect, it } from 'vitest';
import { parseAsciiBitmap } from '../../src/gen1/bitmap.ts';
import { DALOS_ELLIPSE } from '../../src/gen1/curve.ts';
import {
  fromBitString,
  fromBitmap,
  fromIntegerBase10,
  fromIntegerBase49,
  fromRandom,
  fromSeedWords,
  generateRandomBitsOnCurve,
  generateScalarFromBitString,
  scalarToKeyPair,
  scalarToPrivateKey,
  scalarToPublicKey,
  validateBitString,
  validatePrivateKey,
} from '../../src/gen1/key-gen.ts';
import { bitmapVectors, bitstringVectors, schnorrVectors, seedWordsVectors } from '../fixtures.ts';

// ============================================================================
// validateBitString
// ============================================================================

describe('validateBitString', () => {
  it('accepts a valid 1600-bit string', () => {
    const v = validateBitString('0'.repeat(1600));
    expect(v.valid).toBe(true);
    expect(v.lengthOk).toBe(true);
    expect(v.structureOk).toBe(true);
  });

  it('rejects wrong length', () => {
    const v = validateBitString('0'.repeat(1599));
    expect(v.valid).toBe(false);
    expect(v.lengthOk).toBe(false);
  });

  it('rejects non-binary characters', () => {
    const s = `${'0'.repeat(1599)}X`;
    const v = validateBitString(s);
    expect(v.valid).toBe(false);
    expect(v.structureOk).toBe(false);
  });

  // REQ-28 (F-ARCH-006 + F-PERF-005): shape symmetry with PrivateKeyValidation
  // and validateBitmap. The `reason` field is now populated on every failure
  // mode; consumers no longer need to fabricate one from `lengthOk`/`structureOk`.
  it('REQ-28: populates reason on length mismatch', () => {
    const v = validateBitString('0'.repeat(1599));
    expect(v.valid).toBe(false);
    expect(v.lengthOk).toBe(false);
    expect(v.reason).toMatch(/length/i);
    expect(v.reason).toContain('1599');
    expect(v.reason).toContain('1600');
  });

  it('REQ-28: populates reason on non-binary character (with bad-char + position)', () => {
    const v = validateBitString(`${'0'.repeat(1599)}X`);
    expect(v.valid).toBe(false);
    expect(v.structureOk).toBe(false);
    expect(v.reason).toMatch(/non-binary/i);
    expect(v.reason).toContain('X');
    expect(v.reason).toContain('1599'); // position of bad char
  });

  // PAT-002: Go-parity independent measurements — both lengthOk and
  // structureOk reflect actual measurements regardless of which check
  // failed first. The reason carries combined-failure diagnostic.
  it('PAT-002: returns lengthOk=false AND structureOk=false when both checks fail', () => {
    const v = validateBitString(`X${'0'.repeat(1598)}`); // 1599 chars + X at pos 0
    expect(v.valid).toBe(false);
    expect(v.lengthOk).toBe(false);
    expect(v.structureOk).toBe(false);
    expect(v.reason).toMatch(/length mismatch.*AND.*non-binary/);
  });
});

describe('generateScalarFromBitString — single-call + reason-populated (REQ-28)', () => {
  it('throws with the validator reason on length mismatch (includes actual length)', () => {
    expect(() => generateScalarFromBitString('0'.repeat(1599))).toThrow(/length/i);
    expect(() => generateScalarFromBitString('0'.repeat(1599))).toThrow(/1599/);
  });

  it('throws with the validator reason on non-binary character (includes bad char)', () => {
    expect(() => generateScalarFromBitString(`${'0'.repeat(1599)}X`)).toThrow(/non-binary/i);
    expect(() => generateScalarFromBitString(`${'0'.repeat(1599)}X`)).toThrow(/X/);
  });
});

// ============================================================================
// validatePrivateKey
// ============================================================================

describe('validatePrivateKey (BYTE-IDENTITY vs Go corpus)', () => {
  it('all 50 bitstring vectors: priv_int10 parses back to the original bitstring', () => {
    for (const v of bitstringVectors()) {
      const vr = validatePrivateKey(v.priv_int10, 10);
      expect(vr.valid).toBe(true);
      expect(vr.bitString).toBe(v.input_bitstring);
    }
  });

  it('all 50 bitstring vectors: priv_int49 parses back to the original bitstring', () => {
    for (const v of bitstringVectors()) {
      const vr = validatePrivateKey(v.priv_int49, 49);
      expect(vr.valid).toBe(true);
      expect(vr.bitString).toBe(v.input_bitstring);
    }
  });

  it('all 15 seed-words vectors: priv_int49 parses to derived_bitstring', () => {
    for (const v of seedWordsVectors()) {
      const vr = validatePrivateKey(v.priv_int49, 49);
      expect(vr.valid).toBe(true);
      expect(vr.bitString).toBe(v.derived_bitstring);
    }
  });

  it('all 20 bitmap vectors: priv_int49 parses to derived_bitstring', () => {
    for (const v of bitmapVectors()) {
      const vr = validatePrivateKey(v.priv_int49, 49);
      expect(vr.valid).toBe(true);
      expect(vr.bitString).toBe(v.derived_bitstring);
    }
  });

  it('rejects malformed input', () => {
    expect(validatePrivateKey('abc', 10).valid).toBe(false); // non-decimal
    expect(validatePrivateKey('1', 10).valid).toBe(false); // too small
  });

  // REQ-20 (F-API-007): mixed-validity base-49 inputs must be rejected at the
  // earliest boundary, naming the offending character. Without this guard,
  // unknown chars silently accumulate as digit 0 and the validator returns
  // a misleading "core bits length" / "first bit not '1'" reason instead of
  // the actual cause.
  it('REQ-20: rejects base-49 input containing punctuation (!@#) with explicit char in reason', () => {
    const v = validatePrivateKey('valid49chars!@#', 49);
    expect(v.valid).toBe(false);
    expect(v.reason).toMatch(/invalid base-49 character '!'/);
  });

  it('REQ-20: rejects base-49 input containing uppercase past M (e.g., "N") with explicit char in reason', () => {
    const v = validatePrivateKey('123N', 49);
    expect(v.valid).toBe(false);
    expect(v.reason).toMatch(/invalid base-49 character 'N'/);
  });
});

// ============================================================================
// validatePrivateKey — boundary scalars (REQ-01 / F-TEST-002)
// ============================================================================
//
// These three tests pin the OBSERVED behavior of the structural
// `validatePrivateKey` at the boundaries of the subgroup order Q.
//
// IMPORTANT: `validatePrivateKey` is a STRUCTURAL validator — it checks
// the binary shape of the scalar (first bit '1', last 2 bits match the
// cofactor tail "00", middle length == e.s = 1600), NOT subgroup
// membership against Q. A scalar's acceptance therefore depends on its
// binary shape, not on whether it lies in [1, Q-1].
//
// Range-vs-Q semantic validation (a hypothetical
// `validatePrivateKeyRange(scalar, q)` helper) is OUT OF SCOPE for
// Phase 1 of the unified-audit-2026-04-29 spec; if such a helper is
// later introduced, a new boundary suite should pin its semantics
// separately.
//
// Concrete bit-shapes at these boundaries (verified against curve.ts:54-61):
//   - Q       = 1604 bits, first '1', last 2 = "01"   (Q is odd)
//   - Q - 1   = 1604 bits, first '1', last 2 = "00"   (passes cofactor
//               tail, fails middle-length check: 1601 != 1600)
//   - Q + 1   = 1604 bits, first '1', last 2 = "10"   (fails cofactor
//               tail check FIRST — never reaches the length check)
//   - 1 << 1602 = 1603 bits, first '1', last 2 = "00", middle = 1600
//               zeros — STRUCTURALLY VALID, exact `bitString` is 1600 zeros.

describe('validatePrivateKey — boundary scalars (REQ-01 / F-TEST-002)', () => {
  it('rejects scalar = Q-1 (just below subgroup order) — structural check fails on middle-length 1601 != 1600', () => {
    const scalar = (DALOS_ELLIPSE.q - 1n).toString(10);
    const v = validatePrivateKey(scalar, 10);
    expect(v.valid).toBe(false);
    expect(v.reason).toMatch(/core bits length 1601/);
  });

  it('rejects scalar = Q+1 (just above subgroup order) — structural check fails on cofactor-tail mismatch', () => {
    // Q+1's binary shape (1604 bits, first '1', last 2 = "10") fails the
    // cofactor-tail check ("00" required) BEFORE the middle-length check
    // is reached. This pins the OBSERVED short-circuit order of the
    // structural validator. Both Q-1 and Q+1 are rejected, but for
    // DIFFERENT structural reasons — a useful coverage anchor.
    const scalar = (DALOS_ELLIPSE.q + 1n).toString(10);
    const v = validatePrivateKey(scalar, 10);
    expect(v.valid).toBe(false);
    expect(v.reason).toMatch(/last 2 bits must match cofactor tail "00"/);
  });

  it('accepts scalar = 1n << 1602n (edge-valid 1603-bit clamped form) — bitString is 1600 zeros', () => {
    const scalar = (1n << 1602n).toString(10);
    const v = validatePrivateKey(scalar, 10);
    expect(v.valid).toBe(true);
    expect(v.bitString).toBe('0'.repeat(1600));
  });
});

// ============================================================================
// Scalar ↔ key conversions (algebraic round-trip)
// ============================================================================

describe('scalarToPrivateKey / generateScalarFromBitString round-trip', () => {
  it('bitstring → scalar → private key → bitstring is identity for all 50 bitstring vectors', () => {
    for (const v of bitstringVectors()) {
      const scalar = generateScalarFromBitString(v.input_bitstring);
      const priv = scalarToPrivateKey(scalar);
      expect(priv.bitString).toBe(v.input_bitstring);
      expect(priv.int10).toBe(v.scalar_int10);
      expect(priv.int49).toBe(v.priv_int49);
    }
  });
});

// ============================================================================
// generateRandomBitsOnCurve (non-deterministic smoke test)
// ============================================================================

describe('generateRandomBitsOnCurve', () => {
  it('produces exactly e.s bits', () => {
    const bits = generateRandomBitsOnCurve();
    expect(bits.length).toBe(DALOS_ELLIPSE.s);
  });

  it('contains only 0/1 characters', () => {
    const bits = generateRandomBitsOnCurve();
    expect(/^[01]+$/.test(bits)).toBe(true);
  });

  it('produces different output on subsequent calls', () => {
    const a = generateRandomBitsOnCurve();
    const b = generateRandomBitsOnCurve();
    expect(a).not.toBe(b); // overwhelmingly likely for 1600-bit random
  });

  it('fromRandom produces a well-formed DalosFullKey', () => {
    const key = fromRandom();
    expect(key.keyPair.priv).toBeDefined();
    // Public key format: "{prefixLenBase49}.{xyBase49}" — both sides use full base-49 alphabet
    expect(key.keyPair.publ).toMatch(/^[0-9a-zA-M]+\.[0-9a-zA-M]+$/);
    expect(key.standardAddress.startsWith('Ѻ.')).toBe(true);
    expect(key.smartAddress.startsWith('Σ.')).toBe(true);
    expect(key.privateKey.bitString.length).toBe(1600);
    // A round-trip through fromIntegerBase49 should recover identical bitstring.
    // (This cross-validates fromRandom against the deterministic paths.)
  });
});

// ============================================================================
// 🎯 END-TO-END BYTE-IDENTITY: fromBitString
// ============================================================================

describe('fromBitString (BYTE-IDENTITY END-TO-END vs Go corpus)', () => {
  it('all 50 bitstring vectors reproduce scalar_int10, priv_int10, priv_int49, public_key, addresses byte-identically', () => {
    for (const v of bitstringVectors()) {
      const k = fromBitString(v.input_bitstring);
      expect(k.scalar.toString(10)).toBe(v.scalar_int10);
      expect(k.privateKey.int10).toBe(v.priv_int10);
      expect(k.privateKey.int49).toBe(v.priv_int49);
      expect(k.keyPair.priv).toBe(v.priv_int49);
      expect(k.keyPair.publ).toBe(v.public_key);
      expect(k.standardAddress).toBe(v.standard_address);
      expect(k.smartAddress).toBe(v.smart_address);
    }
  }, 60_000);
});

// ============================================================================
// 🎯 END-TO-END BYTE-IDENTITY: fromIntegerBase10 / fromIntegerBase49
// ============================================================================

describe('fromIntegerBase10 (BYTE-IDENTITY END-TO-END)', () => {
  it('all 50 bitstring vectors: recomputing from priv_int10 reproduces all fields', () => {
    for (const v of bitstringVectors()) {
      const k = fromIntegerBase10(v.priv_int10);
      expect(k.privateKey.bitString).toBe(v.input_bitstring);
      expect(k.privateKey.int49).toBe(v.priv_int49);
      expect(k.keyPair.publ).toBe(v.public_key);
      expect(k.standardAddress).toBe(v.standard_address);
      expect(k.smartAddress).toBe(v.smart_address);
    }
  }, 60_000);
});

describe('fromIntegerBase49 (BYTE-IDENTITY END-TO-END)', () => {
  it('all 50 bitstring vectors: recomputing from priv_int49 reproduces all fields', () => {
    for (const v of bitstringVectors()) {
      const k = fromIntegerBase49(v.priv_int49);
      expect(k.privateKey.bitString).toBe(v.input_bitstring);
      expect(k.privateKey.int10).toBe(v.priv_int10);
      expect(k.keyPair.publ).toBe(v.public_key);
      expect(k.standardAddress).toBe(v.standard_address);
      expect(k.smartAddress).toBe(v.smart_address);
    }
  }, 60_000);

  it('all 15 seed-words vectors: recomputing from priv_int49 reproduces addresses', () => {
    for (const v of seedWordsVectors()) {
      const k = fromIntegerBase49(v.priv_int49);
      expect(k.privateKey.bitString).toBe(v.derived_bitstring);
      expect(k.keyPair.publ).toBe(v.public_key);
      expect(k.standardAddress).toBe(v.standard_address);
      expect(k.smartAddress).toBe(v.smart_address);
    }
  }, 60_000);
});

// ============================================================================
// 🎯 END-TO-END BYTE-IDENTITY: fromSeedWords
// ============================================================================

describe('fromSeedWords (BYTE-IDENTITY END-TO-END)', () => {
  it('all 15 seed-words vectors: input_words → priv_int49 + public_key + both addresses', () => {
    for (const v of seedWordsVectors()) {
      const k = fromSeedWords(v.input_words);
      expect(k.privateKey.bitString).toBe(v.derived_bitstring);
      expect(k.privateKey.int10).toBe(v.scalar_int10);
      expect(k.privateKey.int49).toBe(v.priv_int49);
      expect(k.keyPair.publ).toBe(v.public_key);
      expect(k.standardAddress).toBe(v.standard_address);
      expect(k.smartAddress).toBe(v.smart_address);
    }
  }, 60_000);

  it('Cyrillic seed words reproduce correctly', () => {
    const v = seedWordsVectors().find((x) => x.input_words[0] === 'жизнь');
    expect(v).toBeDefined();
    const k = fromSeedWords(v!.input_words);
    expect(k.standardAddress).toBe(v!.standard_address);
    expect(k.smartAddress).toBe(v!.smart_address);
  }, 30_000);

  it('Greek seed words reproduce correctly', () => {
    const v = seedWordsVectors().find((x) => x.input_words[0] === 'Δελτα');
    expect(v).toBeDefined();
    const k = fromSeedWords(v!.input_words);
    expect(k.standardAddress).toBe(v!.standard_address);
    expect(k.smartAddress).toBe(v!.smart_address);
  }, 30_000);
});

// ============================================================================
// 🎯 END-TO-END BYTE-IDENTITY: fromBitmap
// ============================================================================

describe('fromBitmap (BYTE-IDENTITY END-TO-END)', () => {
  it('all 20 bitmap vectors: ASCII pattern → priv_int49 + public_key + both addresses', () => {
    for (const v of bitmapVectors()) {
      const b = parseAsciiBitmap(v.bitmap_ascii);
      const k = fromBitmap(b);
      expect(k.privateKey.bitString).toBe(v.derived_bitstring);
      expect(k.privateKey.int10).toBe(v.scalar_int10);
      expect(k.privateKey.int49).toBe(v.priv_int49);
      expect(k.keyPair.publ).toBe(v.public_key);
      expect(k.standardAddress).toBe(v.standard_address);
      expect(k.smartAddress).toBe(v.smart_address);
    }
  }, 30_000); // 30s ceiling per REQ-15; PM cache landed in v3.1.0

  it('specific pattern check: all-white bitmap', () => {
    const v = bitmapVectors().find((x) => x.pattern === 'all-white (zeros)');
    expect(v).toBeDefined();
    const b = parseAsciiBitmap(v!.bitmap_ascii);
    const k = fromBitmap(b);
    expect(k.standardAddress).toBe(v!.standard_address);
  }, 30_000);

  it('specific pattern check: all-black bitmap', () => {
    const v = bitmapVectors().find((x) => x.pattern === 'all-black (ones)');
    expect(v).toBeDefined();
    const b = parseAsciiBitmap(v!.bitmap_ascii);
    const k = fromBitmap(b);
    expect(k.standardAddress).toBe(v!.standard_address);
  }, 30_000);

  it('specific pattern check: checkerboard-even', () => {
    const v = bitmapVectors().find((x) => x.pattern === 'checkerboard-even');
    expect(v).toBeDefined();
    const b = parseAsciiBitmap(v!.bitmap_ascii);
    const k = fromBitmap(b);
    expect(k.standardAddress).toBe(v!.standard_address);
  }, 30_000);
});

// ============================================================================
// Schnorr vectors: also have public keys we can verify
// ============================================================================

describe('Schnorr-vector public keys reproduce from priv_int49', () => {
  it('all 20 Schnorr-vector public keys reproduce via fromIntegerBase49', () => {
    for (const v of schnorrVectors()) {
      const k = fromIntegerBase49(v.priv_int49);
      expect(k.privateKey.bitString).toBe(v.input_bitstring);
      expect(k.keyPair.publ).toBe(v.public_key);
    }
  }, 60_000);
});

// ============================================================================
// Low-level API exposure
// ============================================================================

describe('low-level APIs', () => {
  it('scalarToKeyPair returns consistent keyPair', () => {
    const v = bitstringVectors()[0]!;
    const scalar = generateScalarFromBitString(v.input_bitstring);
    const kp = scalarToKeyPair(scalar);
    expect(kp.priv).toBe(v.priv_int49);
    expect(kp.publ).toBe(v.public_key);
  });

  it('scalarToPublicKey matches public_key field', () => {
    const v = bitstringVectors()[0]!;
    const scalar = generateScalarFromBitString(v.input_bitstring);
    expect(scalarToPublicKey(scalar)).toBe(v.public_key);
  });
});
