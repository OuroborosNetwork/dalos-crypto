/**
 * Sequential generation of the first N (or any startIndex..startIndex+
 * count-1 range of) Arweave addresses from one seed bitstring, with ONE
 * combined progress stream across the whole run. Direct port of
 * RSA4096/batch.go -- see that file's doc comment for the full design
 * reasoning; this is a port, not a reinterpretation.
 *
 * This is orchestration on top of generateFromBitStringAtIndex/Async
 * (indexed.ts), not a new cryptographic mechanism -- every address is
 * still derived exactly the way indexed.ts already defines. What this
 * file adds is worth getting right ONCE, centrally: a single combined
 * 0..1 progress readout, results delivered incrementally as each
 * address completes, and one settled answer for partial failure (return
 * what completed so far, alongside the error, never silently discarded).
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { generateFromBitStringAtIndex, generateFromBitStringAtIndexAsync } from './indexed.js';
import type { KeyGenResult } from './pipeline.js';
import type { ProgressCallback, ProgressStage } from './progress.js';

/**
 * Reported after every candidate draw of every address in the batch --
 * carries both that address's own detail and the combined, whole-batch
 * view. Matches RSA4096/batch.go's BatchProgressEvent exactly.
 */
export interface BatchProgressEvent {
  /** The absolute address index currently being searched for. */
  index: number;
  /** How many addresses in this batch have already finished. */
  completedCount: number;
  /** The batch's requested count, unchanged for the whole run. */
  totalCount: number;
  /** The CURRENT address's own overallProgress (see ProgressEvent) -- in [0, 1). */
  addressProgress: number;
  /**
   * Folds addressProgress into a single 0..1 value across the WHOLE
   * batch: (completedCount + addressProgress) / totalCount. Honest in
   * the same sense ProgressEvent.overallProgress is honest -- a real
   * weighted combination of N independent memoryless estimates, not a
   * fake animation.
   */
  overallProgress: number;
  /** Passed through from the current address's own ProgressEvent. */
  stage: ProgressStage;
  attempts: number;
}

/** May be omitted (undefined) -- zero overhead, exactly like ProgressCallback. */
export type BatchProgressCallback = (event: BatchProgressEvent) => void;

/**
 * Called once per completed address, in order, immediately as each one
 * finishes -- lets a caller render results progressively rather than
 * waiting for the whole batch. May be omitted.
 */
export type BatchResultCallback = (index: number, result: KeyGenResult) => void;

/** Thrown by both batch functions on invalid (startIndex, count) input. */
export class BatchRangeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BatchRangeError';
  }
}

/**
 * Thrown when a batch fails partway through. Unlike a plain Error, this
 * carries the results ALREADY completed (in order) so a caller doesn't
 * have to lose already-completed, multi-second-cost prime searches just
 * because a later index failed -- matches RSA4096/batch.go's "return
 * partial results alongside the error" semantics, which Go expresses via
 * a normal `([]*KeyGenResult, error)` return but TS expresses via this
 * dedicated error subclass carrying `completed`.
 */
export class BatchGenerationError extends Error {
  readonly completed: readonly KeyGenResult[];
  readonly failedIndex: number;
  readonly cause: unknown;

  constructor(
    message: string,
    completed: readonly KeyGenResult[],
    failedIndex: number,
    cause: unknown,
  ) {
    super(message);
    this.name = 'BatchGenerationError';
    this.completed = completed;
    this.failedIndex = failedIndex;
    this.cause = cause;
  }
}

const MAX_INDEX = 0xffffffff;

function validateRange(startIndex: number, count: number): void {
  if (!Number.isInteger(count) || count < 1) {
    throw new BatchRangeError(`count must be an integer >= 1, got ${count}`);
  }
  if (!Number.isInteger(startIndex) || startIndex < 0) {
    throw new BatchRangeError(`startIndex must be a non-negative integer, got ${startIndex}`);
  }
  if (startIndex + count - 1 > MAX_INDEX) {
    throw new BatchRangeError('startIndex + count - 1 exceeds the maximum index');
  }
}

/**
 * Synchronous batch generation -- see {@link generateBatchFromBitStringAsync}
 * for the event-loop-yielding variant a browser UI should use instead
 * (this variant blocks the calling thread for the ENTIRE batch, same
 * tradeoff as generateFromBitString vs generateFromBitStringAsync).
 *
 * startIndex === 0 with count === N gives "the first N addresses" -- the
 * primary use case -- but any starting point works (e.g. startIndex=100,
 * count=50 for "the next 50 after the first hundred").
 */
export function generateBatchFromBitString(
  seedBitString: string,
  startIndex: number,
  count: number,
  onProgress?: BatchProgressCallback,
  onResult?: BatchResultCallback,
): KeyGenResult[] {
  validateRange(startIndex, count);

  const results: KeyGenResult[] = [];
  for (let i = 0; i < count; i++) {
    const index = startIndex + i;
    const innerProgress: ProgressCallback | undefined = onProgress
      ? (ev) => {
          onProgress({
            index,
            completedCount: i,
            totalCount: count,
            addressProgress: ev.overallProgress,
            overallProgress: (i + ev.overallProgress) / count,
            stage: ev.stage,
            attempts: ev.attempts,
          });
        }
      : undefined;

    let result: KeyGenResult;
    try {
      result = generateFromBitStringAtIndex(seedBitString, index, innerProgress);
    } catch (cause) {
      throw new BatchGenerationError(
        `generateBatchFromBitString: failed at index ${index} (${i} of ${count} addresses completed before this): ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
        results,
        index,
        cause,
      );
    }

    results.push(result);
    onResult?.(index, result);
  }

  return results;
}

/**
 * Async variant of {@link generateBatchFromBitString}, built on
 * {@link generateFromBitStringAtIndexAsync} -- yields to the event loop
 * during each address's prime search so a browser UI thread stays
 * responsive for the WHOLE batch, not just one address. This is the
 * recommended entry point for any UI that lets a user generate multiple
 * Arweave addresses from one seed.
 */
export async function generateBatchFromBitStringAsync(
  seedBitString: string,
  startIndex: number,
  count: number,
  onProgress?: BatchProgressCallback,
  onResult?: BatchResultCallback,
): Promise<KeyGenResult[]> {
  validateRange(startIndex, count);

  const results: KeyGenResult[] = [];
  for (let i = 0; i < count; i++) {
    const index = startIndex + i;
    const innerProgress: ProgressCallback | undefined = onProgress
      ? (ev) => {
          onProgress({
            index,
            completedCount: i,
            totalCount: count,
            addressProgress: ev.overallProgress,
            overallProgress: (i + ev.overallProgress) / count,
            stage: ev.stage,
            attempts: ev.attempts,
          });
        }
      : undefined;

    let result: KeyGenResult;
    try {
      result = await generateFromBitStringAtIndexAsync(seedBitString, index, innerProgress);
    } catch (cause) {
      throw new BatchGenerationError(
        `generateBatchFromBitStringAsync: failed at index ${index} (${i} of ${count} addresses completed before this): ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
        results,
        index,
        cause,
      );
    }

    results.push(result);
    onResult?.(index, result);
  }

  return results;
}
