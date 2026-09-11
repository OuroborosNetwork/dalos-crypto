/**
 * Progress reporting for the prime search, so a caller (typically a UI) can
 * render a live progress indicator during the multi-second key generation.
 * Direct port of RSA4096/progress.go -- see that file's doc comment for the
 * full reasoning.
 *
 * PURELY OBSERVATIONAL. Reporting progress never reads from the seed
 * stream, never branches on any secret-derived value, and never affects
 * the deterministic output.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { CANDIDATE_BITS } from './candidate.js';

/** Matches RSA4096/progress.go's ProgressStage exactly. */
export type ProgressStage = 'p' | 'q';

export const STAGE_SEARCHING_P: ProgressStage = 'p';
export const STAGE_SEARCHING_Q: ProgressStage = 'q';

/** Matches RSA4096/progress.go's ProgressEvent exactly. */
export interface ProgressEvent {
  stage: ProgressStage;
  /** Candidates drawn so far in THIS stage (resets when the q search begins). */
  attempts: number;
  /**
   * Probabilistic ESTIMATE in [0, 1) of how likely this stage has already
   * found its prime, given `attempts` draws so far -- an honest estimate
   * derived from the same prime-density math the design doc uses to
   * predict the ~710-draw average, not a guarantee. The search can and
   * sometimes will run past stageProgress === 0.99; the stage ends,
   * deterministically, the instant a real prime is actually found.
   */
  stageProgress: number;
  /**
   * Folds stageProgress into a single 0..1 value across BOTH stages,
   * weighting the p-search as the first half and the q-search as the
   * second half. Convenience only.
   */
  overallProgress: number;
}

/** Receives one ProgressEvent per candidate draw. May be omitted (undefined). */
export type ProgressCallback = (event: ProgressEvent) => void;

/**
 * P(a single random odd `CANDIDATE_BITS`-bit integer, with its top two
 * bits forced to 1, is prime), by the prime number theorem. Matches
 * RSA4096/progress.go's primeProbabilityPerDraw exactly.
 */
const PRIME_PROBABILITY_PER_DRAW = 2 / (CANDIDATE_BITS * Math.LN2);

/**
 * Returns P(a prime has been found within `attempts` independent draws):
 * 1 - (1 - p)^attempts, the geometric-distribution CDF. Matches
 * RSA4096/progress.go's estimateStageProgress exactly.
 */
function estimateStageProgress(attempts: number): number {
  return 1 - (1 - PRIME_PROBABILITY_PER_DRAW) ** attempts;
}

/**
 * Calls onProgress (if defined) with a freshly computed ProgressEvent.
 * Matches RSA4096/progress.go's reportProgress exactly.
 */
export function reportProgress(
  onProgress: ProgressCallback | undefined,
  stage: ProgressStage,
  attempts: number,
): void {
  if (!onProgress) return;
  const stageProgress = estimateStageProgress(attempts);
  const overallProgress = stage === STAGE_SEARCHING_Q ? 0.5 + stageProgress / 2 : stageProgress / 2;
  onProgress({ stage, attempts, stageProgress, overallProgress });
}
