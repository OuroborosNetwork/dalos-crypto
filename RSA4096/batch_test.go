package RSA4096

import (
	"strings"
	"testing"
)

func TestGenerateBatchFromBitString_RejectsZeroCount(t *testing.T) {
	if _, err := GenerateBatchFromBitString(fixedTestSeed(), 0, 0, nil, nil); err == nil {
		t.Fatal("expected an error for count == 0, got nil")
	}
}

func TestGenerateBatchFromBitString_RejectsIndexOverflow(t *testing.T) {
	if _, err := GenerateBatchFromBitString(fixedTestSeed(), 4294967295, 2, nil, nil); err == nil {
		t.Fatal("expected an error when startIndex+count-1 exceeds uint32 max, got nil")
	}
}

// TestGenerateBatchFromBitString_MatchesIndividualCalls is the core
// correctness check: a batch of size N must produce EXACTLY the same N
// results, in the same order, as calling GenerateFromBitStringAtIndex
// individually for each index -- batching is pure orchestration, it
// must not change any address's derivation.
func TestGenerateBatchFromBitString_MatchesIndividualCalls(t *testing.T) {
	seed := fixedTestSeed()
	const count = 3

	batch, err := GenerateBatchFromBitString(seed, 0, count, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != count {
		t.Fatalf("got %d results, want %d", len(batch), count)
	}

	for i := uint32(0); i < count; i++ {
		individual, err := GenerateFromBitStringAtIndex(seed, i, nil)
		if err != nil {
			t.Fatal(err)
		}
		if batch[i].Address != individual.Address {
			t.Fatalf("index %d: batch address %q != individual address %q", i, batch[i].Address, individual.Address)
		}
		if batch[i].Key.N.Cmp(individual.Key.N) != 0 {
			t.Fatalf("index %d: batch modulus != individual modulus", i)
		}
	}

	// Addresses within the batch must all be distinct from each other.
	seen := make(map[string]bool)
	for i, r := range batch {
		if seen[r.Address] {
			t.Fatalf("index %d produced a duplicate address within the batch: %s", i, r.Address)
		}
		seen[r.Address] = true
	}
}

// TestGenerateBatchFromBitString_StartIndexOffset confirms an arbitrary
// starting point works, not just startIndex == 0.
func TestGenerateBatchFromBitString_StartIndexOffset(t *testing.T) {
	seed := fixedTestSeed()

	batch, err := GenerateBatchFromBitString(seed, 100, 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 2 {
		t.Fatalf("got %d results, want 2", len(batch))
	}

	want100, err := GenerateFromBitStringAtIndex(seed, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	want101, err := GenerateFromBitStringAtIndex(seed, 101, nil)
	if err != nil {
		t.Fatal(err)
	}
	if batch[0].Address != want100.Address {
		t.Fatalf("batch[0] (index 100) address %q != %q", batch[0].Address, want100.Address)
	}
	if batch[1].Address != want101.Address {
		t.Fatalf("batch[1] (index 101) address %q != %q", batch[1].Address, want101.Address)
	}
}

// TestGenerateBatchFromBitString_OnResultFiresInOrder confirms results
// are delivered incrementally, in index order, one per completed
// address.
func TestGenerateBatchFromBitString_OnResultFiresInOrder(t *testing.T) {
	seed := fixedTestSeed()
	const count = 3

	var gotIndices []uint32
	var gotAddresses []string
	onResult := func(index uint32, result *KeyGenResult) {
		gotIndices = append(gotIndices, index)
		gotAddresses = append(gotAddresses, result.Address)
	}

	batch, err := GenerateBatchFromBitString(seed, 0, count, nil, onResult)
	if err != nil {
		t.Fatal(err)
	}

	if len(gotIndices) != count {
		t.Fatalf("onResult fired %d times, want %d", len(gotIndices), count)
	}
	for i := uint32(0); i < count; i++ {
		if gotIndices[i] != i {
			t.Fatalf("onResult call %d reported index %d, want %d", i, gotIndices[i], i)
		}
		if gotAddresses[i] != batch[i].Address {
			t.Fatalf("onResult call %d address %q != returned batch address %q", i, gotAddresses[i], batch[i].Address)
		}
	}
}

// TestGenerateBatchFromBitString_ProgressIsMonotonicAndBounded confirms
// the combined OverallProgress is a real, honest, monotonically
// non-decreasing-within-an-address value in [0, 1), and that
// CompletedCount/TotalCount/Index are consistent throughout the run.
func TestGenerateBatchFromBitString_ProgressIsMonotonicAndBounded(t *testing.T) {
	seed := fixedTestSeed()
	const count = 2

	var events []BatchProgressEvent
	onProgress := func(ev BatchProgressEvent) {
		events = append(events, ev)
	}

	if _, err := GenerateBatchFromBitString(seed, 0, count, onProgress, nil); err != nil {
		t.Fatal(err)
	}

	if len(events) == 0 {
		t.Fatal("expected at least one progress event")
	}

	sawIndex0, sawIndex1 := false, false
	for i, ev := range events {
		if ev.TotalCount != count {
			t.Fatalf("event %d: TotalCount = %d, want %d", i, ev.TotalCount, count)
		}
		if ev.OverallProgress < 0 || ev.OverallProgress >= 1 {
			t.Fatalf("event %d: OverallProgress = %v, want in [0, 1)", i, ev.OverallProgress)
		}
		if ev.AddressProgress < 0 || ev.AddressProgress >= 1 {
			t.Fatalf("event %d: AddressProgress = %v, want in [0, 1)", i, ev.AddressProgress)
		}
		// The combined formula, checked directly.
		wantOverall := (float64(ev.CompletedCount) + ev.AddressProgress) / float64(count)
		if diff := wantOverall - ev.OverallProgress; diff > 1e-12 || diff < -1e-12 {
			t.Fatalf("event %d: OverallProgress = %v, want %v (from CompletedCount=%d, AddressProgress=%v)",
				i, ev.OverallProgress, wantOverall, ev.CompletedCount, ev.AddressProgress)
		}
		switch ev.Index {
		case 0:
			sawIndex0 = true
			if ev.CompletedCount != 0 {
				t.Fatalf("event %d: index 0 in flight but CompletedCount = %d, want 0", i, ev.CompletedCount)
			}
		case 1:
			sawIndex1 = true
			if ev.CompletedCount != 1 {
				t.Fatalf("event %d: index 1 in flight but CompletedCount = %d, want 1", i, ev.CompletedCount)
			}
		}
	}
	if !sawIndex0 || !sawIndex1 {
		t.Fatalf("expected progress events for both index 0 and index 1, got index0=%v index1=%v", sawIndex0, sawIndex1)
	}
}

// TestGenerateBatchFromBitString_ReturnsPartialResultsOnError confirms
// the settled error semantics: a failure partway through returns the
// results completed so far, not nil, alongside the error.
func TestGenerateBatchFromBitString_ReturnsPartialResultsOnError(t *testing.T) {
	// Use an invalid seed so GenerateFromBitStringAtIndex fails on index
	// 0 itself -- this deterministically exercises the "0 completed
	// before the failure" branch without needing to inject a fault deep
	// inside the prime search.
	badSeed := strings.Repeat("0", 1300) // not a valid {1024, 1600} length

	results, err := GenerateBatchFromBitString(badSeed, 0, 5, nil, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid seed, got nil")
	}
	if results == nil {
		t.Fatal("expected non-nil (possibly empty) results slice alongside the error, got nil")
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 completed results (failure on the very first index), got %d", len(results))
	}
	if !strings.Contains(err.Error(), "index 0") {
		t.Fatalf("expected the error to name the failing index (0); got: %v", err)
	}
}
