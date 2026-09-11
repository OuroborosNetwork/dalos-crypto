// Progress reporting for the prime search, so a caller (typically a UI) can
// render a live progress indicator during the multi-second key generation.
//
// PURELY OBSERVATIONAL. Reporting progress never reads from the seed
// stream, never branches on any secret-derived value, and never affects the
// deterministic output -- it is a read-only tap on the same `attempts`
// counter FindPrime already maintains, called after every candidate draw.
// Passing a nil ProgressFunc anywhere in this package (as every existing
// caller does) reproduces byte-for-byte the exact same output as before
// this file existed.
package RSA4096

import "math"

// ProgressStage identifies which half of the search a ProgressEvent
// describes. Key generation is always: search for p, then (continuing on
// the same stream) search for q, then assemble the key -- there is no
// stage for key assembly itself, since that step is pure arithmetic on
// already-found primes and takes microseconds, not seconds.
type ProgressStage string

const (
	StageSearchingP ProgressStage = "p"
	StageSearchingQ ProgressStage = "q"
)

// ProgressEvent is reported to a ProgressFunc after every candidate draw.
type ProgressEvent struct {
	Stage ProgressStage
	// Attempts is the number of candidates drawn so far in THIS stage
	// (resets to 1 when the q search begins; does not carry over from p).
	Attempts int
	// StageProgress is a probabilistic ESTIMATE in [0, 1) of how likely
	// this stage is to have already found its prime, given `Attempts`
	// draws so far. It is derived from the same prime-density math the
	// design doc uses to predict the ~710-draw average (see
	// estimateStageProgress's doc comment) -- an honest estimate, not a
	// guarantee. The search can and sometimes will run past
	// StageProgress == 0.99; the stage ends, deterministically, the
	// instant a real prime is actually found, regardless of what this
	// number said. Suitable for driving a progress bar that a UI wants
	// to keep moving even though the TRUE remaining time is unknowable
	// in advance (the search is a memoryless process with no fixed
	// total).
	StageProgress float64
	// OverallProgress folds StageProgress into a single 0..1 value across
	// BOTH stages, weighting the p-search as the first half and the
	// q-search as the second half (both stages have the same expected
	// length, so an even split is the honest default). Convenience only --
	// equivalent to computing it yourself from Stage + StageProgress.
	OverallProgress float64
}

// ProgressFunc receives one ProgressEvent per candidate draw. May be nil,
// in which case no progress is computed or reported at all (zero overhead).
type ProgressFunc func(ProgressEvent)

// primeProbabilityPerDraw is P(a single random odd `candidateBits`-bit
// integer, with its top two bits forced to 1, is prime), by the prime
// number theorem: density of primes near 2^candidateBits is
// ~1/(candidateBits * ln 2), and restricting to odd numbers only doubles
// that density (half of all integers are already excluded by being even).
// This is the same ~1/710 figure the design doc derives and validates
// empirically against the actual measured attempt counts in
// testvectors/v2_rsa4096.json.
var primeProbabilityPerDraw = 2.0 / (float64(candidateBits) * math.Ln2)

// estimateStageProgress returns P(a prime has been found within `attempts`
// independent draws), treating the search as the memoryless geometric
// process it actually is: 1 - (1 - p)^attempts, where p is
// primeProbabilityPerDraw. This is the textbook geometric-distribution CDF,
// not a heuristic -- it is the honest answer to "given everything we know
// (nothing except how many draws have happened), how likely is it we
// should already be done?"
func estimateStageProgress(attempts int) float64 {
	return 1 - math.Pow(1-primeProbabilityPerDraw, float64(attempts))
}

// reportProgress calls onProgress (if non-nil) with a freshly computed
// ProgressEvent for the given stage/attempts. Centralized here so
// FindPrime's loop stays a one-line call regardless of how the estimate
// formula evolves.
func reportProgress(onProgress ProgressFunc, stage ProgressStage, attempts int) {
	if onProgress == nil {
		return
	}
	stageProgress := estimateStageProgress(attempts)
	overall := stageProgress / 2
	if stage == StageSearchingQ {
		overall = 0.5 + stageProgress/2
	}
	onProgress(ProgressEvent{
		Stage:           stage,
		Attempts:        attempts,
		StageProgress:   stageProgress,
		OverallProgress: overall,
	})
}
