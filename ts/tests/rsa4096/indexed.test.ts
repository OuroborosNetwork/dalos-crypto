/**
 * Tests for indexed.ts -- deterministic derivation of MULTIPLE
 * independent Arweave addresses from the SAME seed bitstring. Mirrors
 * RSA4096/indexed_test.go's cases exactly, so a divergence in either
 * language's derivation shows up as a test failure in that language
 * specifically, not just a silent cross-language mismatch.
 *
 * Most cases exercise deriveIndexedSeedBitString directly (cheap, no
 * prime search); only a few full generateFromBitStringAtIndex calls are
 * needed to prove the end-to-end feature actually works.
 */

import { describe, expect, it } from 'vitest';
import {
  MAX_INDEX,
  deriveIndexedSeedBitString,
  generateFromBitString,
  generateFromBitStringAtIndex,
  generateFromBitStringAtIndexAsync,
  selfCheckTextbookRSA,
} from '../../src/rsa4096/index.js';
import { hashBytesToBitString } from '../../src/rsa4096/indexed.js';

const dalosTestSeedLen = 1600;
const apolloTestSeedLen = 1024;

function fixedTestSeedOfLength(length: number): string {
  const pattern = '1101001011010110';
  let s = '';
  while (s.length < length) s += pattern;
  return s.slice(0, length);
}

const fixedTestSeed = () => fixedTestSeedOfLength(dalosTestSeedLen);

describe('deriveIndexedSeedBitString (cheap, no prime search)', () => {
  it('produces a seed of the same length as the input, for both blessed lengths', () => {
    for (const length of [apolloTestSeedLen, dalosTestSeedLen]) {
      const seed = fixedTestSeedOfLength(length);
      const derived = deriveIndexedSeedBitString(seed, 1);
      expect(derived.length).toBe(length);
      expect(derived).toMatch(/^[01]+$/);
    }
  });

  it('is deterministic: same (seed, index) -> same derived seed', () => {
    const seed = fixedTestSeed();
    expect(deriveIndexedSeedBitString(seed, 42)).toBe(deriveIndexedSeedBitString(seed, 42));
  });

  it('different indices diverge', () => {
    const seed = fixedTestSeed();
    const derived = [1, 2, 3, 1000000, MAX_INDEX].map((idx) =>
      deriveIndexedSeedBitString(seed, idx),
    );
    expect(new Set(derived).size).toBe(derived.length);
  });

  it('different parent seeds diverge for the same index', () => {
    const seedA = fixedTestSeed();
    const seedB = (seedA[0] === '0' ? '1' : '0') + seedA.slice(1);
    expect(deriveIndexedSeedBitString(seedA, 7)).not.toBe(deriveIndexedSeedBitString(seedB, 7));
  });

  it('rejects a seed length outside {1024, 1600}', () => {
    expect(() => deriveIndexedSeedBitString('0'.repeat(1300), 1)).toThrow();
  });

  it('rejects an out-of-range index', () => {
    expect(() => deriveIndexedSeedBitString(fixedTestSeed(), -1)).toThrow();
    expect(() => deriveIndexedSeedBitString(fixedTestSeed(), MAX_INDEX + 1)).toThrow();
    expect(() => deriveIndexedSeedBitString(fixedTestSeed(), 1.5)).toThrow();
  });
});

describe('hashBytesToBitString', () => {
  it('matches the known-value case from the Go test suite', () => {
    expect(hashBytesToBitString(new Uint8Array([0x00, 0xff, 0xa5]))).toBe(
      '000000001111111110100101',
    );
  });
});

describe('generateFromBitStringAtIndex (a few real, end-to-end runs)', () => {
  // Core backward-compatibility guarantee: address #0 via the new
  // indexed API must be byte-identical to calling generateFromBitString
  // directly, forever -- this is what keeps every already-published,
  // already-frozen result valid.
  it('index 0 matches generateFromBitString called directly', () => {
    const seed = fixedTestSeed();
    const direct = generateFromBitString(seed);
    const indexed = generateFromBitStringAtIndex(seed, 0);

    expect(indexed.key.n).toBe(direct.key.n);
    expect(indexed.address).toBe(direct.address);
    expect(indexed.pAttempts).toBe(direct.pAttempts);
    expect(indexed.qAttempts).toBe(direct.qAttempts);
  });

  it('a non-zero index produces a real, independent, valid key', () => {
    const seed = fixedTestSeed();
    const addr0 = generateFromBitStringAtIndex(seed, 0);
    const addr1 = generateFromBitStringAtIndex(seed, 1);

    expect(addr1.address).not.toBe(addr0.address);
    expect(addr1.key.n).not.toBe(addr0.key.n);
    expect(() => selfCheckTextbookRSA(addr1.key)).not.toThrow();
  });

  it('any index is directly reachable without generating the ones before it (pure function, not chained state)', () => {
    const seed = fixedTestSeed();
    const first = generateFromBitStringAtIndex(seed, 777);
    const again = generateFromBitStringAtIndex(seed, 777);
    expect(again.address).toBe(first.address);
  });

  it('the async variant produces byte-identical output to the sync variant, for a non-zero index', async () => {
    const seed = fixedTestSeed();
    const sync = generateFromBitStringAtIndex(seed, 3);
    const async_ = await generateFromBitStringAtIndexAsync(seed, 3);
    expect(async_.key.n).toBe(sync.key.n);
    expect(async_.address).toBe(sync.address);
  });
});
