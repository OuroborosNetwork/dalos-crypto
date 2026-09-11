/**
 * Tests for batch.ts -- combined-progress, sequential generation of a
 * range of Arweave addresses from one seed. Mirrors
 * RSA4096/batch_test.go's cases exactly.
 */

import { describe, expect, it } from 'vitest';
import {
  BatchGenerationError,
  BatchRangeError,
  generateBatchFromBitString,
  generateBatchFromBitStringAsync,
  generateFromBitStringAtIndex,
} from '../../src/rsa4096/index.js';

function fixedTestSeedOfLength(length: number): string {
  const pattern = '1101001011010110';
  let s = '';
  while (s.length < length) s += pattern;
  return s.slice(0, length);
}

const fixedTestSeed = () => fixedTestSeedOfLength(1600);

describe('generateBatchFromBitString: input validation', () => {
  it('rejects count === 0', () => {
    expect(() => generateBatchFromBitString(fixedTestSeed(), 0, 0)).toThrow(BatchRangeError);
  });

  it('rejects a startIndex/count combination that overflows the max index', () => {
    expect(() => generateBatchFromBitString(fixedTestSeed(), 4294967295, 2)).toThrow(
      BatchRangeError,
    );
  });

  it('rejects a negative or non-integer startIndex/count', () => {
    expect(() => generateBatchFromBitString(fixedTestSeed(), -1, 1)).toThrow(BatchRangeError);
    expect(() => generateBatchFromBitString(fixedTestSeed(), 0, 1.5)).toThrow(BatchRangeError);
  });
});

describe('generateBatchFromBitString: real, end-to-end runs', () => {
  // 6 full RSA-4096 generations in one test (3 batch + 3 individual
  // re-derivations to compare against) genuinely exceeds vitest's
  // 15s default -- explicit timeout, not a hang.
  it('matches individual generateFromBitStringAtIndex calls, in order, with distinct addresses', () => {
    const seed = fixedTestSeed();
    const count = 3;

    const batch = generateBatchFromBitString(seed, 0, count);
    expect(batch.length).toBe(count);

    for (let i = 0; i < count; i++) {
      const individual = generateFromBitStringAtIndex(seed, i);
      expect(batch[i]!.address).toBe(individual.address);
      expect(batch[i]!.key.n).toBe(individual.key.n);
    }

    const addresses = batch.map((r) => r.address);
    expect(new Set(addresses).size).toBe(count);
  }, 60_000);

  it('supports an arbitrary startIndex, not just 0', () => {
    const seed = fixedTestSeed();
    const batch = generateBatchFromBitString(seed, 100, 2);
    expect(batch.length).toBe(2);
    expect(batch[0]!.address).toBe(generateFromBitStringAtIndex(seed, 100).address);
    expect(batch[1]!.address).toBe(generateFromBitStringAtIndex(seed, 101).address);
  });

  it('delivers results incrementally via onResult, in index order', () => {
    const seed = fixedTestSeed();
    const count = 3;
    const gotIndices: number[] = [];
    const gotAddresses: string[] = [];

    const batch = generateBatchFromBitString(seed, 0, count, undefined, (index, result) => {
      gotIndices.push(index);
      gotAddresses.push(result.address);
    });

    expect(gotIndices).toEqual([0, 1, 2]);
    expect(gotAddresses).toEqual(batch.map((r) => r.address));
  });

  it('reports combined progress that is honest, bounded, and matches the stated formula', () => {
    const seed = fixedTestSeed();
    const count = 2;
    const events: Array<{
      index: number;
      completedCount: number;
      totalCount: number;
      addressProgress: number;
      overallProgress: number;
    }> = [];

    generateBatchFromBitString(seed, 0, count, (ev) => {
      events.push(ev);
    });

    expect(events.length).toBeGreaterThan(0);
    const sawIndex = new Set<number>();
    for (const ev of events) {
      expect(ev.totalCount).toBe(count);
      expect(ev.overallProgress).toBeGreaterThanOrEqual(0);
      expect(ev.overallProgress).toBeLessThan(1);
      expect(ev.addressProgress).toBeGreaterThanOrEqual(0);
      expect(ev.addressProgress).toBeLessThan(1);
      expect(ev.overallProgress).toBeCloseTo((ev.completedCount + ev.addressProgress) / count, 12);
      sawIndex.add(ev.index);
      if (ev.index === 0) expect(ev.completedCount).toBe(0);
      if (ev.index === 1) expect(ev.completedCount).toBe(1);
    }
    expect(sawIndex.has(0)).toBe(true);
    expect(sawIndex.has(1)).toBe(true);
  });

  it('throws BatchGenerationError carrying the completed-so-far results on failure', () => {
    const badSeed = '0'.repeat(1300); // not a valid {1024, 1600} length

    let caught: unknown;
    try {
      generateBatchFromBitString(badSeed, 0, 5);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(BatchGenerationError);
    const err = caught as BatchGenerationError;
    expect(err.completed).toEqual([]);
    expect(err.failedIndex).toBe(0);
    expect(err.message).toContain('index 0');
  });

  it('async variant produces byte-identical output to the sync variant', async () => {
    const seed = fixedTestSeed();
    const sync = generateBatchFromBitString(seed, 0, 2);
    const async_ = await generateBatchFromBitStringAsync(seed, 0, 2);
    expect(async_.map((r) => r.address)).toEqual(sync.map((r) => r.address));
    expect(async_.map((r) => r.key.n)).toEqual(sync.map((r) => r.key.n));
  });
});
