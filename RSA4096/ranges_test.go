package RSA4096

import "testing"

// --- collectSortedUniqueIndices: cheap, no prime search ------------------

func TestCollectSortedUniqueIndices_AlwaysIncludesZero(t *testing.T) {
	indices, err := collectSortedUniqueIndices([]IndexRange{{Start: 10, End: 12}})
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{0, 10, 11, 12}
	if !equalUint32Slices(indices, want) {
		t.Fatalf("got %v, want %v", indices, want)
	}
}

func TestCollectSortedUniqueIndices_MultipleRangesSortedAndDeduped(t *testing.T) {
	// Deliberately out of order and overlapping (5-7 and 6-9 share 6,7),
	// with one range that already includes 0.
	indices, err := collectSortedUniqueIndices([]IndexRange{
		{Start: 6, End: 9},
		{Start: 0, End: 2},
		{Start: 5, End: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{0, 1, 2, 5, 6, 7, 8, 9}
	if !equalUint32Slices(indices, want) {
		t.Fatalf("got %v, want %v", indices, want)
	}
}

func TestCollectSortedUniqueIndices_NoRangesIsJustZero(t *testing.T) {
	indices, err := collectSortedUniqueIndices(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !equalUint32Slices(indices, []uint32{0}) {
		t.Fatalf("got %v, want [0]", indices)
	}
}

func TestCollectSortedUniqueIndices_SingleElementRange(t *testing.T) {
	indices, err := collectSortedUniqueIndices([]IndexRange{{Start: 42, End: 42}})
	if err != nil {
		t.Fatal(err)
	}
	if !equalUint32Slices(indices, []uint32{0, 42}) {
		t.Fatalf("got %v, want [0, 42]", indices)
	}
}

func TestCollectSortedUniqueIndices_RejectsStartGreaterThanEnd(t *testing.T) {
	if _, err := collectSortedUniqueIndices([]IndexRange{{Start: 10, End: 5}}); err == nil {
		t.Fatal("expected an error for Start > End, got nil")
	}
}

func TestCollectSortedUniqueIndices_HandlesMaxUint32EndWithoutHanging(t *testing.T) {
	// A range whose End is math.MaxUint32 must terminate (not overflow
	// into an infinite loop) -- confirmed by using a Start close to the
	// top so the test completes quickly either way.
	const start = 4294967293 // MaxUint32 - 2
	indices, err := collectSortedUniqueIndices([]IndexRange{{Start: start, End: 4294967295}})
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{0, 4294967293, 4294967294, 4294967295}
	if !equalUint32Slices(indices, want) {
		t.Fatalf("got %v, want %v", indices, want)
	}
}

func equalUint32Slices(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- GenerateFromBitStringAtRanges: real, end-to-end runs ----------------

// TestGenerateFromBitStringAtRanges_AlwaysIncludesIndexZero confirms the
// always-0 guarantee holds for the full generation path, not just the
// index-collection helper.
func TestGenerateFromBitStringAtRanges_AlwaysIncludesIndexZero(t *testing.T) {
	seed := fixedTestSeed()

	results, err := GenerateFromBitStringAtRanges(seed, []IndexRange{{Start: 5, End: 6}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3 (index 0, 5, 6)", len(results))
	}

	want0, err := GenerateFromBitStringAtIndex(seed, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Address != want0.Address {
		t.Fatalf("first result address %q != index-0 address %q -- index 0 was not first/included correctly", results[0].Address, want0.Address)
	}
}

// TestGenerateFromBitStringAtRanges_MultipleRangesMatchIndividualCalls is
// the core correctness check: the union of several ranges must produce
// exactly the same results, in ascending-index order, as calling
// GenerateFromBitStringAtIndex individually for each unique index.
func TestGenerateFromBitStringAtRanges_MultipleRangesMatchIndividualCalls(t *testing.T) {
	seed := fixedTestSeed()

	results, err := GenerateFromBitStringAtRanges(seed, []IndexRange{
		{Start: 1, End: 2},
		{Start: 10, End: 10},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	wantIndices := []uint32{0, 1, 2, 10}
	if len(results) != len(wantIndices) {
		t.Fatalf("got %d results, want %d", len(results), len(wantIndices))
	}
	for i, idx := range wantIndices {
		individual, err := GenerateFromBitStringAtIndex(seed, idx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if results[i].Address != individual.Address {
			t.Fatalf("result %d (index %d): address %q != individual address %q", i, idx, results[i].Address, individual.Address)
		}
	}
}

// TestGenerateFromBitStringAtRanges_OnResultFiresInAscendingOrder confirms
// results are delivered incrementally in ascending-index order, even
// when the input ranges were given out of order.
func TestGenerateFromBitStringAtRanges_OnResultFiresInAscendingOrder(t *testing.T) {
	seed := fixedTestSeed()

	var gotIndices []uint32
	onResult := func(index uint32, result *KeyGenResult) {
		gotIndices = append(gotIndices, index)
	}

	// Ranges deliberately out of order.
	_, err := GenerateFromBitStringAtRanges(seed, []IndexRange{
		{Start: 8, End: 8},
		{Start: 1, End: 1},
	}, nil, onResult)
	if err != nil {
		t.Fatal(err)
	}

	want := []uint32{0, 1, 8}
	if !equalUint32Slices(gotIndices, want) {
		t.Fatalf("onResult fired for indices %v, want %v (ascending, deduped, always-0)", gotIndices, want)
	}
}

// TestGenerateFromBitStringAtRanges_ProgressTotalCountMatchesUniqueIndices
// confirms TotalCount in progress events reflects the DEDUPLICATED count,
// not the naive sum of range sizes.
func TestGenerateFromBitStringAtRanges_ProgressTotalCountMatchesUniqueIndices(t *testing.T) {
	seed := fixedTestSeed()

	var lastTotal uint32
	onProgress := func(ev BatchProgressEvent) {
		lastTotal = ev.TotalCount
	}

	// {0,2} ∪ {1,3} = {0,1,2,3} -- 4 unique indices, NOT 3+3=6.
	_, err := GenerateFromBitStringAtRanges(seed, []IndexRange{
		{Start: 0, End: 2},
		{Start: 1, End: 3},
	}, onProgress, nil)
	if err != nil {
		t.Fatal(err)
	}

	if lastTotal != 4 {
		t.Fatalf("TotalCount = %d, want 4 (deduplicated union of {0,2} and {1,3})", lastTotal)
	}
}
