// File ranges.go — generalizes batch.go's single contiguous range to an
// arbitrary LIST of inclusive ranges (e.g. 1-100, 134-167, 234-777),
// deduplicated and sorted, with index 0 ALWAYS included regardless of
// whether any given range covers it.
//
// This is orchestration on top of GenerateFromBitStringAtIndex
// (indexed.go), exactly like batch.go — no new derivation, just a
// different (more general) way of choosing which indices to generate.
// Deliberately a SEPARATE function from GenerateBatchFromBitString, not
// a reimplementation of it: that function is already published and
// tested with an exact contract (generate precisely [startIndex,
// startIndex+count-1], nothing else, no implicit index 0 unless it's
// in range) — retrofitting "always include 0" onto it would silently
// change its output for existing callers (e.g. GenerateBatchFromBitString
// (seed, 100, 2) would suddenly also return index 0). This file adds a
// capability; it does not touch batch.go's contract.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
package RSA4096

import (
	"fmt"
	"sort"
)

// IndexRange is an inclusive [Start, End] range of address indices.
type IndexRange struct {
	Start, End uint32
}

// GenerateFromBitStringAtRanges derives Arweave addresses for every
// index in the union of the given ranges (each inclusive) — e.g.
// {1,100}, {134,167}, {234,777} — from the same seed bitstring.
//
// Index 0 is ALWAYS included, regardless of whether any range covers
// it: it's the seed's primary/default address (see
// GenerateFromBitStringAtIndex), and a caller asking for "these other
// ranges too" should get it for free rather than having to remember to
// ask for it separately.
//
// Indices are deduplicated automatically — one appearing in more than
// one range, or covered by the always-0 rule and also explicitly
// requested, is generated exactly once. Output is sorted ascending by
// index, deterministically, regardless of what order the ranges were
// given in or whether they overlap.
//
// Same combined-progress and partial-failure semantics as
// GenerateBatchFromBitString (see batch.go): one progress readout
// across the whole deduplicated set, results delivered incrementally
// via onResult in ascending-index order, and every result completed so
// far returned alongside any error (never discarded).
func GenerateFromBitStringAtRanges(
	seedBitString string,
	ranges []IndexRange,
	onProgress BatchProgressFunc,
	onResult BatchResultFunc,
) ([]*KeyGenResult, error) {
	indices, err := collectSortedUniqueIndices(ranges)
	if err != nil {
		return nil, err
	}

	results := make([]*KeyGenResult, 0, len(indices))
	total := uint32(len(indices))
	for i, idx := range indices {
		completedSoFar := uint32(i)

		var innerProgress ProgressFunc
		if onProgress != nil {
			innerProgress = func(ev ProgressEvent) {
				overall := (float64(completedSoFar) + ev.OverallProgress) / float64(total)
				onProgress(BatchProgressEvent{
					Index:           idx,
					CompletedCount:  completedSoFar,
					TotalCount:      total,
					AddressProgress: ev.OverallProgress,
					OverallProgress: overall,
					Stage:           ev.Stage,
					Attempts:        ev.Attempts,
				})
			}
		}

		result, err := GenerateFromBitStringAtIndex(seedBitString, idx, innerProgress)
		if err != nil {
			return results, fmt.Errorf(
				"GenerateFromBitStringAtRanges: failed at index %d (%d of %d completed before this): %w",
				idx, i, total, err,
			)
		}

		results = append(results, result)
		if onResult != nil {
			onResult(idx, result)
		}
	}

	return results, nil
}

// collectSortedUniqueIndices validates ranges, flattens their union
// (plus the always-included index 0) into a deduplicated slice, and
// sorts it ascending.
func collectSortedUniqueIndices(ranges []IndexRange) ([]uint32, error) {
	seen := map[uint32]bool{0: true}
	indices := []uint32{0}

	for _, r := range ranges {
		if r.Start > r.End {
			return nil, fmt.Errorf(
				"GenerateFromBitStringAtRanges: range [%d, %d] has Start > End", r.Start, r.End,
			)
		}
		// Loop written so the End == math.MaxUint32 case terminates
		// correctly instead of wrapping: the `idx++` post-statement
		// only runs after a full iteration completes, and `break`
		// exits before that post-statement ever executes -- so
		// checking `idx == r.End` (the CURRENT value, pre-increment)
		// and breaking there means idx can never advance past
		// math.MaxUint32, even when r.End IS math.MaxUint32.
		for idx := r.Start; ; idx++ {
			if !seen[idx] {
				seen[idx] = true
				indices = append(indices, idx)
			}
			if idx == r.End {
				break
			}
		}
	}

	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
	return indices, nil
}
