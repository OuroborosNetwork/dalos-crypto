// File batch.go — sequential generation of the first N (or any
// startIndex..startIndex+count-1 range of) Arweave addresses from one
// seed bitstring, with ONE combined progress stream across the whole
// run.
//
// This is orchestration on top of GenerateFromBitStringAtIndex
// (indexed.go), not a new cryptographic mechanism — every address is
// still derived exactly the way indexed.go already defines. What this
// file adds is the part worth getting right ONCE, centrally, rather than
// leaving every caller (Codex, the StoicDigest demo, any future tool) to
// reimplement the same combined-progress arithmetic and error semantics
// slightly differently:
//
//   - a single 0..1 progress readout across the ENTIRE batch, not just
//     the address currently being searched for (see
//     BatchProgressEvent.OverallProgress);
//   - results delivered incrementally, one per completed address, via
//     onResult — so a caller can render address #1, #2, #3... as they
//     land instead of waiting for the whole batch to finish;
//   - one settled answer for "what happens if address 42 of 100 fails":
//     return the 41 already-completed results (not nil, not discarded)
//     ALONGSIDE the error, since each one cost real, multi-second work.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
package RSA4096

import (
	"errors"
	"fmt"
	"math"
)

// BatchProgressEvent is reported after every candidate draw of every
// address in the batch (i.e. at the same frequency ProgressEvent already
// fires for a single address) — it carries both that address's own
// detail and the combined, whole-batch view.
type BatchProgressEvent struct {
	// Index is the absolute address index currently being searched for
	// (startIndex + CompletedCount, while it's in flight).
	Index uint32
	// CompletedCount is how many addresses in this batch have already
	// finished (0 while the first address is still being searched for).
	CompletedCount uint32
	// TotalCount is the batch's requested count, unchanged for the
	// whole run — convenience so a caller doesn't have to keep it
	// separately.
	TotalCount uint32
	// AddressProgress is the CURRENT address's own OverallProgress
	// (see ProgressEvent) — in [0, 1).
	AddressProgress float64
	// OverallProgress folds AddressProgress into a single 0..1 value
	// across the WHOLE batch: (CompletedCount + AddressProgress) /
	// TotalCount. Honest in the same sense ProgressEvent.OverallProgress
	// is honest — a real weighted combination of N independent
	// memoryless estimates, not a fake animation.
	OverallProgress float64
	// Stage and Attempts pass through the current address's own
	// ProgressEvent detail, for a caller that wants both a fine-grained
	// per-address bar and the combined one.
	Stage    ProgressStage
	Attempts int
}

// BatchProgressFunc receives one BatchProgressEvent per candidate draw,
// across every address in the batch. May be nil (zero overhead, exactly
// like ProgressFunc).
type BatchProgressFunc func(BatchProgressEvent)

// BatchResultFunc is called once per completed address, in order,
// immediately as each one finishes — lets a caller render results
// progressively rather than waiting for the whole batch. May be nil.
type BatchResultFunc func(index uint32, result *KeyGenResult)

// GenerateBatchFromBitString derives `count` independent Arweave
// addresses — indices startIndex, startIndex+1, ..., startIndex+count-1
// — from the same seed bitstring, sequentially (not in parallel — each
// address's prime search is CPU-bound and independent, so there is no
// benefit to interleaving them, and sequential execution is what makes
// "one combined progress bar" a coherent, linearly-advancing thing to
// show), reporting one COMBINED progress stream across the whole run.
//
// startIndex == 0 with count == N gives "the first N addresses" — the
// primary use case — but any starting point is directly usable (e.g.
// startIndex=100, count=50 for "the next 50 after the first hundred"),
// consistent with indexed.go's "any index directly reachable" design.
//
// On error partway through, returns the results completed SO FAR (in
// order, one entry per completed index, length == the number completed)
// ALONGSIDE the error — never nil-with-error, since each completed
// result cost real, multi-second work that a caller should not have to
// discard just because a later index failed.
func GenerateBatchFromBitString(
	seedBitString string,
	startIndex, count uint32,
	onProgress BatchProgressFunc,
	onResult BatchResultFunc,
) ([]*KeyGenResult, error) {
	if count == 0 {
		return nil, errors.New("GenerateBatchFromBitString: count must be at least 1")
	}
	if uint64(startIndex)+uint64(count)-1 > uint64(math.MaxUint32) {
		return nil, errors.New("GenerateBatchFromBitString: startIndex + count - 1 exceeds the maximum index")
	}

	results := make([]*KeyGenResult, 0, count)
	for i := uint32(0); i < count; i++ {
		idx := startIndex + i

		var innerProgress ProgressFunc
		if onProgress != nil {
			completedSoFar := i // captured by value per-iteration (Go 1.22+ loop var semantics; see go.mod)
			innerProgress = func(ev ProgressEvent) {
				overall := (float64(completedSoFar) + ev.OverallProgress) / float64(count)
				onProgress(BatchProgressEvent{
					Index:           idx,
					CompletedCount:  completedSoFar,
					TotalCount:      count,
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
				"GenerateBatchFromBitString: failed at index %d (%d of %d addresses completed before this): %w",
				idx, i, count, err,
			)
		}

		results = append(results, result)
		if onResult != nil {
			onResult(idx, result)
		}
	}

	return results, nil
}
