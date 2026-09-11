// Tests for the seed-word contract settled 2026-09-11: 1-256 words,
// each 1-256 glyphs, every glyph one of the 256 in the DALOS
// CharacterMatrix. Mirrors ts/tests/gen1/hashing.test.ts's
// "validateSeedWords / seedWordsToBitString input gate" block
// glyph-for-glyph, so a bug that only shows up in one language's
// counting (e.g. byte vs. rune) is caught here too.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.

package Elliptic

import (
    "strings"
    "testing"
)

func TestValidateSeedWords_AcceptsBoundaryMinimum(t *testing.T) {
    if err := ValidateSeedWords([]string{"a"}); err != nil {
        t.Fatalf("expected 1 word / 1 glyph to be accepted, got error: %v", err)
    }
}

func TestValidateSeedWords_AcceptsBoundaryMaximum(t *testing.T) {
    words := make([]string, MaxSeedWords)
    for i := range words {
        words[i] = strings.Repeat("a", MaxSeedWordGlyphs)
    }
    if err := ValidateSeedWords(words); err != nil {
        t.Fatalf("expected %d words of %d glyphs each to be accepted, got error: %v", MaxSeedWords, MaxSeedWordGlyphs, err)
    }
}

func TestValidateSeedWords_RejectsZeroWords(t *testing.T) {
    if err := ValidateSeedWords([]string{}); err == nil {
        t.Fatal("expected 0 words to be rejected")
    }
}

func TestValidateSeedWords_RejectsTooManyWords(t *testing.T) {
    words := make([]string, MaxSeedWords+1)
    for i := range words {
        words[i] = "a"
    }
    if err := ValidateSeedWords(words); err == nil {
        t.Fatalf("expected %d words to be rejected", MaxSeedWords+1)
    }
}

func TestValidateSeedWords_RejectsEmptyStringWord(t *testing.T) {
    if err := ValidateSeedWords([]string{"hello", ""}); err == nil {
        t.Fatal("expected an empty-string word (0 glyphs) to be rejected")
    }
}

func TestValidateSeedWords_RejectsWordTooLong(t *testing.T) {
    tooLong := strings.Repeat("a", MaxSeedWordGlyphs+1)
    if err := ValidateSeedWords([]string{tooLong}); err == nil {
        t.Fatalf("expected a %d-glyph word to be rejected", MaxSeedWordGlyphs+1)
    }
}

func TestValidateSeedWords_RejectsCharacterOutsideMatrix(t *testing.T) {
    if err := ValidateSeedWords([]string{"中文"}); err == nil {
        t.Fatal("expected Chinese characters (outside the 256-glyph matrix) to be rejected")
    }
}

func TestValidateSeedWords_RejectsCyrillicLatinHomoglyphs(t *testing.T) {
    // "привет" contains р and е, both excluded from the DALOS Cyrillic
    // subset specifically because they are homoglyphs of Latin letters
    // already present in the matrix (р looks like Latin p, е looks like
    // Latin e).
    if err := ValidateSeedWords([]string{"привет"}); err == nil {
        t.Fatal("expected 'привет' (contains excluded homoglyph letters) to be rejected")
    }
}

func TestValidateSeedWords_RejectsGreekHomoglyphsAndAccents(t *testing.T) {
    // "κόσμε" contains accented alpha/omicron forms and bare omicron,
    // none of which are in the matrix (accented Greek vowels aren't
    // represented at all; ο/υ are excluded as Latin homoglyphs).
    if err := ValidateSeedWords([]string{"κόσμε"}); err == nil {
        t.Fatal("expected 'κόσμε' (accented / homoglyph-excluded letters) to be rejected")
    }
}

func TestValidateSeedWords_AcceptsInCharsetCyrillicAndGreekFixtures(t *testing.T) {
    if err := ValidateSeedWords([]string{"жизнь", "плющ"}); err != nil {
        t.Fatalf("expected in-charset Cyrillic fixture to be accepted, got: %v", err)
    }
    if err := ValidateSeedWords([]string{"Δελτα", "Σιγμα", "Ωμεγα"}); err != nil {
        t.Fatalf("expected in-charset Greek fixture to be accepted, got: %v", err)
    }
}

func TestSeedWordsToBitString_PropagatesValidationError(t *testing.T) {
    e := DalosEllipse()
    if _, err := e.SeedWordsToBitString([]string{}); err == nil {
        t.Fatal("expected SeedWordsToBitString([]) to return an error")
    }
    if _, err := e.SeedWordsToBitString([]string{"привет"}); err == nil {
        t.Fatal("expected SeedWordsToBitString with an out-of-charset word to return an error")
    }
}
