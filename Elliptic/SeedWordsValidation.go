// File SeedWordsValidation.go — the single, canonical seed-word input
// gate for every DALOS entry point (Go CLI, Go library callers, and by
// mirrored contract, the TypeScript port).
//
// Final restriction level (settled 2026-09-11, superseding the CLI-only,
// inconsistent checks previously scattered in Dalos.go):
//   1. Every glyph in every seed word must be one of the 256 glyphs in
//      the DALOS CharacterMatrix (Elliptic/CharacterMatrix.go) — the
//      same curated Latin/Greek/Cyrillic/digit/currency alphabet already
//      used to render Ѻ./Σ. addresses. Nothing outside that set is
//      accepted, in any language — this is a closed alphabet, not "any
//      UTF-8 character".
//   2. 1 to 256 words.
//   3. 1 to 256 glyphs per word.
//
// Deliberately NOT baked into every code path unconditionally at the
// lowest possible layer — it IS baked into the one production entry
// point every real caller goes through, `(*Ellipse).SeedWordsToBitString`,
// so it is impossible to reach key generation from seed words without
// passing this gate, in Go or (via the mirrored TS validator in
// ts/src/gen1/hashing.ts) in TypeScript. Within that valid range, the
// user's choice of words is entirely their own responsibility — this
// function does not judge word "quality", only the three counted limits
// above.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.

package Elliptic

import (
    "fmt"
    "unicode/utf8"
)

const (
    // MinSeedWords is the fewest words a seed phrase may contain.
    MinSeedWords = 1
    // MaxSeedWords is the most words a seed phrase may contain.
    MaxSeedWords = 256
    // MinSeedWordGlyphs is the fewest glyphs a single seed word may contain.
    MinSeedWordGlyphs = 1
    // MaxSeedWordGlyphs is the most glyphs a single seed word may contain.
    MaxSeedWordGlyphs = 256
)

// characterSetCache is the 256-glyph DALOS alphabet as a set, built once
// from the same cached matrix CharacterMatrix() returns, for O(1)
// membership tests instead of the old O(256) nested-loop scan.
var characterSetCache = makeCharacterSet()

func makeCharacterSet() map[rune]struct{} {
    matrix := CharacterMatrix()
    set := make(map[rune]struct{}, 256)
    for i := 0; i < 16; i++ {
        for j := 0; j < 16; j++ {
            set[matrix[i][j]] = struct{}{}
        }
    }
    return set
}

// IsCharInMatrix reports whether r is one of the 256 glyphs in the DALOS
// CharacterMatrix. Exported so callers other than ValidateSeedWords (the
// Go CLI's own diagnostics, in particular) can reuse the same source of
// truth instead of re-scanning the matrix by hand.
func IsCharInMatrix(r rune) bool {
    _, ok := characterSetCache[r]
    return ok
}

// ValidateSeedWords enforces the DALOS seed-word contract described in
// this file's header. Returns nil if words is acceptable input for
// SeedWordsToBitString; otherwise a descriptive error identifying which
// rule failed and, where useful, which word/character triggered it.
func ValidateSeedWords(words []string) error {
    if len(words) < MinSeedWords || len(words) > MaxSeedWords {
        return fmt.Errorf(
            "seed words: expected between %d and %d words, got %d",
            MinSeedWords, MaxSeedWords, len(words),
        )
    }
    for i, word := range words {
        glyphCount := utf8.RuneCountInString(word)
        if glyphCount < MinSeedWordGlyphs || glyphCount > MaxSeedWordGlyphs {
            return fmt.Errorf(
                "seed word %d (%q): expected between %d and %d glyphs, got %d",
                i, word, MinSeedWordGlyphs, MaxSeedWordGlyphs, glyphCount,
            )
        }
        for _, r := range word {
            if !IsCharInMatrix(r) {
                return fmt.Errorf(
                    "seed word %d (%q): character %q (U+%04X) is not one of the 256 glyphs in the DALOS character set",
                    i, word, r, r,
                )
            }
        }
    }
    return nil
}
