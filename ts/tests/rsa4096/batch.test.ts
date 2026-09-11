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
  generateFromBitStringAtIndexAsync,
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
  // Prefer the Async variants throughout this block, even where the
  // property under test isn't specifically about async behavior.
  // Reason (found 2026-09-11 via a real CI failure, not a hypothetical):
  // the SYNC api has no internal yield points, so chaining several full
  // generations back-to-back inside one synchronous `it()` body can
  // block the worker's event loop long enough that it misses vitest's
  // own internal worker-RPC heartbeat ("[vitest-worker]: Timeout calling
  // onTaskUpdate", a 60s birpc default with no exposed vitest.config.ts
  // override) -- a false-positive infrastructure failure with every
  // actual assertion passing. The Async variants yield every 8 candidate
  // draws (see primesearch.ts), which keeps the RPC channel serviced
  // throughout even when a test chains multiple full generations. The
  // one test that must call the sync API directly (to prove sync/async
  // parity) is deliberately kept minimal (a single 2-address batch).
  // 6 total generations in this one test (3 in the batch + 3 individual
  // re-derivations to compare against) -- switching to the Async variants
  // fixed the worker-RPC heartbeat issue (see above), but 6 chained
  // generations can still comfortably exceed the 30s *global* testTimeout
  // on CI's slower hardware even with no single generation being slow in
  // isolation. Explicit longer timeout, not a hang.
  it('matches individual generateFromBitStringAtIndexAsync calls, in order, with distinct addresses', async () => {
    const seed = fixedTestSeed();
    const count = 3;

    const batch = await generateBatchFromBitStringAsync(seed, 0, count);
    expect(batch.length).toBe(count);

    for (let i = 0; i < count; i++) {
      const individual = await generateFromBitStringAtIndexAsync(seed, i);
      expect(batch[i]!.address).toBe(individual.address);
      expect(batch[i]!.key.n).toBe(individual.key.n);
    }

    const addresses = batch.map((r) => r.address);
    expect(new Set(addresses).size).toBe(count);
  }, 120_000);

  // 4 total generations (2 in the batch + 2 individual comparisons) --
  // explicit timeout for the same margin reasons as above.
  it('supports an arbitrary startIndex, not just 0', async () => {
    const seed = fixedTestSeed();
    const batch = await generateBatchFromBitStringAsync(seed, 100, 2);
    expect(batch.length).toBe(2);
    expect(batch[0]!.address).toBe((await generateFromBitStringAtIndexAsync(seed, 100)).address);
    expect(batch[1]!.address).toBe((await generateFromBitStringAtIndexAsync(seed, 101)).address);
  }, 90_000);

  // 3 total generations (one batch of 3) -- explicit timeout for margin.
  it('delivers results incrementally via onResult, in index order', async () => {
    const seed = fixedTestSeed();
    const count = 3;
    const gotIndices: number[] = [];
    const gotAddresses: string[] = [];

    const batch = await generateBatchFromBitStringAsync(
      seed,
      0,
      count,
      undefined,
      (index, result) => {
        gotIndices.push(index);
        gotAddresses.push(result.address);
      },
    );

    expect(gotIndices).toEqual([0, 1, 2]);
    expect(gotAddresses).toEqual(batch.map((r) => r.address));
  }, 90_000);

  it('reports combined progress that is honest, bounded, and matches the stated formula', async () => {
    const seed = fixedTestSeed();
    const count = 2;
    const events: Array<{
      index: number;
      completedCount: number;
      totalCount: number;
      addressProgress: number;
      overallProgress: number;
    }> = [];

    await generateBatchFromBitStringAsync(seed, 0, count, (ev) => {
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
  }, 60_000);

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

  // 4 total generations (2 sync + 2 async) -- this is the one test that
  // must call the sync API directly, kept deliberately minimal (a
  // 2-address batch) per the header comment above.
  it('async variant produces byte-identical output to the sync variant', async () => {
    const seed = fixedTestSeed();
    const sync = generateBatchFromBitString(seed, 0, 2);
    const async_ = await generateBatchFromBitStringAsync(seed, 0, 2);
    expect(async_.map((r) => r.address)).toEqual(sync.map((r) => r.address));
    expect(async_.map((r) => r.key.n)).toEqual(sync.map((r) => r.key.n));
  }, 60_000);
});
