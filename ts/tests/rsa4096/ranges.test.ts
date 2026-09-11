/**
 * Tests for ranges.ts -- multi-range, always-includes-0, deduplicated
 * generation. Mirrors RSA4096/ranges_test.go's cases exactly.
 */

import { describe, expect, it } from 'vitest';
import {
  BatchGenerationError,
  BatchRangeError,
  generateFromBitStringAtIndex,
  generateFromBitStringAtIndexAsync,
  generateFromBitStringAtRanges,
  generateFromBitStringAtRangesAsync,
} from '../../src/rsa4096/index.js';

function fixedTestSeedOfLength(length: number): string {
  const pattern = '1101001011010110';
  let s = '';
  while (s.length < length) s += pattern;
  return s.slice(0, length);
}

const fixedTestSeed = () => fixedTestSeedOfLength(1600);

describe('generateFromBitStringAtRanges: input validation', () => {
  it('rejects start > end', () => {
    expect(() => generateFromBitStringAtRanges(fixedTestSeed(), [{ start: 10, end: 5 }])).toThrow(
      BatchRangeError,
    );
  });

  it('rejects a negative or non-integer bound', () => {
    expect(() => generateFromBitStringAtRanges(fixedTestSeed(), [{ start: -1, end: 5 }])).toThrow(
      BatchRangeError,
    );
    expect(() => generateFromBitStringAtRanges(fixedTestSeed(), [{ start: 0, end: 5.5 }])).toThrow(
      BatchRangeError,
    );
  });

  it('rejects a range exceeding the maximum index', () => {
    expect(() =>
      generateFromBitStringAtRanges(fixedTestSeed(), [{ start: 0, end: 0x100000000 }]),
    ).toThrow(BatchRangeError);
  });

  it('an empty ranges array still generates index 0 alone', () => {
    const seed = fixedTestSeed();
    const results = generateFromBitStringAtRanges(seed, []);
    expect(results.length).toBe(1);
    expect(results[0]!.address).toBe(generateFromBitStringAtIndex(seed, 0).address);
  }, 60_000);
});

describe('generateFromBitStringAtRanges: real, end-to-end runs', () => {
  it('always includes index 0, even when no range covers it', async () => {
    const seed = fixedTestSeed();
    const results = await generateFromBitStringAtRangesAsync(seed, [{ start: 5, end: 6 }]);
    expect(results.length).toBe(3); // 0, 5, 6
    expect(results[0]!.address).toBe((await generateFromBitStringAtIndexAsync(seed, 0)).address);
  }, 60_000);

  // Uses the Async variants throughout -- 8 total generations (4 in the
  // ranges call + 4 individual comparisons) chained with zero internal
  // yield points on the sync API can miss vitest's own internal
  // worker-RPC heartbeat (see batch.test.ts's header comment for the
  // full story); the Async variants yield every 8 candidate draws and
  // keep the RPC channel serviced throughout.
  it('multiple ranges match individual generateFromBitStringAtIndexAsync calls, in ascending order', async () => {
    const seed = fixedTestSeed();
    const results = await generateFromBitStringAtRangesAsync(seed, [
      { start: 1, end: 2 },
      { start: 10, end: 10 },
    ]);

    const wantIndices = [0, 1, 2, 10];
    expect(results.length).toBe(wantIndices.length);
    for (let i = 0; i < wantIndices.length; i++) {
      const individual = await generateFromBitStringAtIndexAsync(seed, wantIndices[i]!);
      expect(results[i]!.address).toBe(individual.address);
    }
  }, 120_000);

  it('onResult fires in ascending-index order, deduplicated, even when ranges are given out of order', async () => {
    const seed = fixedTestSeed();
    const gotIndices: number[] = [];

    await generateFromBitStringAtRangesAsync(
      seed,
      [
        { start: 8, end: 8 },
        { start: 1, end: 1 },
      ],
      undefined,
      (index) => {
        gotIndices.push(index);
      },
    );

    expect(gotIndices).toEqual([0, 1, 8]);
  }, 60_000);

  it('progress totalCount reflects the deduplicated union, not the naive sum of range sizes', async () => {
    const seed = fixedTestSeed();
    let lastTotal = -1;

    // {0..2} ∪ {1..3} = {0,1,2,3} -- 4 unique indices, not 3+3=6.
    await generateFromBitStringAtRangesAsync(
      seed,
      [
        { start: 0, end: 2 },
        { start: 1, end: 3 },
      ],
      (ev) => {
        lastTotal = ev.totalCount;
      },
    );

    expect(lastTotal).toBe(4);
  }, 60_000);

  it('throws BatchGenerationError carrying completed-so-far results on failure', () => {
    const badSeed = '0'.repeat(1300); // not a valid {1024, 1600} length

    let caught: unknown;
    try {
      generateFromBitStringAtRanges(badSeed, [{ start: 1, end: 5 }]);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(BatchGenerationError);
    const err = caught as BatchGenerationError;
    expect(err.completed).toEqual([]);
    expect(err.failedIndex).toBe(0); // index 0 is always attempted first
  });

  it('async variant produces byte-identical output to the sync variant', async () => {
    const seed = fixedTestSeed();
    const ranges = [{ start: 1, end: 1 }];
    const sync = generateFromBitStringAtRanges(seed, ranges);
    const async_ = await generateFromBitStringAtRangesAsync(seed, ranges);
    expect(async_.map((r) => r.address)).toEqual(sync.map((r) => r.address));
  }, 90_000);
});
