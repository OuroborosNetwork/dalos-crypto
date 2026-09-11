/**
 * Generalizes batch.ts's single contiguous range to an arbitrary LIST
 * of inclusive ranges (e.g. 1-100, 134-167, 234-777), deduplicated and
 * sorted, with index 0 ALWAYS included regardless of whether any given
 * range covers it. Direct port of RSA4096/ranges.go -- see that file's
 * doc comment for the full design reasoning; this is a port, not a
 * reinterpretation.
 *
 * This is orchestration on top of generateFromBitStringAtIndex/Async
 * (indexed.ts), exactly like batch.ts -- no new derivation, just a
 * different (more general) way of choosing which indices to generate.
 * Deliberately a SEPARATE module from batch.ts, not a reimplementation
 * of it: generateBatchFromBitString is already published and tested
 * with an exact contract (generate precisely [startIndex, startIndex +
 * count - 1], nothing else, no implicit index 0 unless it's in range) --
 * retrofitting "always include 0" onto it would silently change its
 * output for existing callers. This file adds a capability; it does not
 * touch batch.ts's contract.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import {
  BatchGenerationError,
  type BatchProgressCallback,
  BatchRangeError,
  type BatchResultCallback,
} from './batch.js';
import { generateFromBitStringAtIndex, generateFromBitStringAtIndexAsync } from './indexed.js';
import type { KeyGenResult } from './pipeline.js';
import type { ProgressCallback } from './progress.js';

/** An inclusive `[start, end]` range of address indices. */
export interface IndexRange {
  start: number;
  end: number;
}

const MAX_INDEX = 0xffffffff;

/**
 * Validates `ranges` and flattens their union -- plus the always-
 * included index 0 -- into a deduplicated, ascending-sorted array.
 * Matches RSA4096/ranges.go's collectSortedUniqueIndices exactly.
 */
function collectSortedUniqueIndices(ranges: readonly IndexRange[]): number[] {
  const seen = new Set<number>([0]);
  const indices: number[] = [0];

  for (const range of ranges) {
    if (!Number.isInteger(range.start) || !Number.isInteger(range.end) || range.start < 0) {
      throw new BatchRangeError(
        `range [${range.start}, ${range.end}] must have non-negative integer bounds`,
      );
    }
    if (range.start > range.end) {
      throw new BatchRangeError(`range [${range.start}, ${range.end}] has start > end`);
    }
    if (range.end > MAX_INDEX) {
      throw new BatchRangeError(`range [${range.start}, ${range.end}] exceeds the maximum index`);
    }
    for (let idx = range.start; idx <= range.end; idx++) {
      if (!seen.has(idx)) {
        seen.add(idx);
        indices.push(idx);
      }
    }
  }

  indices.sort((a, b) => a - b);
  return indices;
}

/**
 * Derives Arweave addresses for every index in the union of the given
 * ranges (each inclusive) -- e.g. `{start:1,end:100}`,
 * `{start:134,end:167}`, `{start:234,end:777}` -- from the same seed
 * bitstring.
 *
 * Index 0 is ALWAYS included, regardless of whether any range covers
 * it: it's the seed's primary/default address (see
 * {@link generateFromBitStringAtIndex}), and a caller asking for
 * "these other ranges too" should get it for free rather than having
 * to remember to ask for it separately.
 *
 * Indices are deduplicated automatically -- one appearing in more than
 * one range, or covered by the always-0 rule and also explicitly
 * requested, is generated exactly once. Output is sorted ascending by
 * index, deterministically, regardless of what order the ranges were
 * given in or whether they overlap.
 *
 * Same combined-progress and partial-failure semantics as
 * `generateBatchFromBitString` (batch.ts): one progress readout across
 * the whole deduplicated set, results delivered incrementally via
 * `onResult` in ascending-index order, and every result completed so
 * far attached to a thrown `BatchGenerationError` (never silently
 * discarded).
 *
 * Synchronous -- see {@link generateFromBitStringAtRangesAsync} for the
 * event-loop-yielding variant a browser UI should use instead.
 */
export function generateFromBitStringAtRanges(
  seedBitString: string,
  ranges: readonly IndexRange[],
  onProgress?: BatchProgressCallback,
  onResult?: BatchResultCallback,
): KeyGenResult[] {
  const indices = collectSortedUniqueIndices(ranges);
  const results: KeyGenResult[] = [];
  const total = indices.length;

  for (let i = 0; i < total; i++) {
    const idx = indices[i]!;
    const innerProgress: ProgressCallback | undefined = onProgress
      ? (ev) => {
          onProgress({
            index: idx,
            completedCount: i,
            totalCount: total,
            addressProgress: ev.overallProgress,
            overallProgress: (i + ev.overallProgress) / total,
            stage: ev.stage,
            attempts: ev.attempts,
          });
        }
      : undefined;

    let result: KeyGenResult;
    try {
      result = generateFromBitStringAtIndex(seedBitString, idx, innerProgress);
    } catch (cause) {
      throw new BatchGenerationError(
        `generateFromBitStringAtRanges: failed at index ${idx} (${i} of ${total} completed before this): ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
        results,
        idx,
        cause,
      );
    }

    results.push(result);
    onResult?.(idx, result);
  }

  return results;
}

/**
 * Async variant of {@link generateFromBitStringAtRanges}, built on
 * {@link generateFromBitStringAtIndexAsync} -- yields to the event loop
 * during each address's prime search so a browser UI thread stays
 * responsive for the whole run. This is the recommended entry point for
 * any UI that lets a user request multiple ranges of Arweave addresses
 * from one seed.
 */
export async function generateFromBitStringAtRangesAsync(
  seedBitString: string,
  ranges: readonly IndexRange[],
  onProgress?: BatchProgressCallback,
  onResult?: BatchResultCallback,
): Promise<KeyGenResult[]> {
  const indices = collectSortedUniqueIndices(ranges);
  const results: KeyGenResult[] = [];
  const total = indices.length;

  for (let i = 0; i < total; i++) {
    const idx = indices[i]!;
    const innerProgress: ProgressCallback | undefined = onProgress
      ? (ev) => {
          onProgress({
            index: idx,
            completedCount: i,
            totalCount: total,
            addressProgress: ev.overallProgress,
            overallProgress: (i + ev.overallProgress) / total,
            stage: ev.stage,
            attempts: ev.attempts,
          });
        }
      : undefined;

    let result: KeyGenResult;
    try {
      result = await generateFromBitStringAtIndexAsync(seedBitString, idx, innerProgress);
    } catch (cause) {
      throw new BatchGenerationError(
        `generateFromBitStringAtRangesAsync: failed at index ${idx} (${i} of ${total} completed before this): ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
        results,
        idx,
        cause,
      );
    }

    results.push(result);
    onResult?.(idx, result);
  }

  return results;
}
