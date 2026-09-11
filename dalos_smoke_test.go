package main

import (
    "context"
    "os/exec"
    "strings"
    "testing"
    "time"
)

// TestCLI_InvalidIntegerFlag_ExitsNonZeroWithError is the integrated-driver
// regression guard for the empty-string-sentinel + caller-update contract
// across ProcessIntegerFlag and Dalos.go's base-10 integer call site
// (CLI flag -i10, internally named intaFlag). It spawns the compiled binary
// as a subprocess via `go run` and asserts:
//
//   1. The subprocess exits non-zero (caller hit os.Exit(1) after observing
//      the empty-string sentinel from ProcessIntegerFlag).
//   2. Combined stdout+stderr contains "Error: Invalid private key." — the
//      diagnostic emitted by ProcessIntegerFlag itself.
//   3. Combined stdout+stderr contains "Aborting -i10 base-10 key generation."
//      — the per-call-site message emitted by Dalos.go BEFORE os.Exit(1).
//      The "-i10" token references the actual user-facing flag (matches
//      the input the user typed). This proves the caller-update landed
//      and the sentinel check is wired.
//
// A 30-second deadline gates the worst-case failure mode: if the caller
// update accidentally allows downstream flow to reach SaveBitString's
// fmt.Scanln password prompt, the subprocess would block on stdin forever.
// CommandContext + DeadlineExceeded converts that hang into a clean test
// diagnostic instead of stalling the entire `go test` run.
//
// The test invokes `go run .` (Phase 10 v4.0.0 cutover from
// `go run Dalos.go` — the carve-out splits package main across Dalos.go
// + print.go + process.go, so the single-file compile no longer resolves
// the relocated free functions ProcessIntegerFlag / ProcessKeyGeneration
// / etc.). CI environments and local dev shells both have `go` on PATH;
// no separate build artifact is managed.
func TestCLI_InvalidIntegerFlag_ExitsNonZeroWithError(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // F-MED-004 (v4.0.2): password must be >= 16 chars to satisfy the
    // new strength gate. Use a 20-char placeholder so the gate doesn't
    // fire BEFORE the -i10 validation we're actually testing here.
    cmd := exec.CommandContext(ctx, "go", "run", ".", "-g", "-i10", "not_an_integer", "-p", "test-password-1234567")
    out, err := cmd.CombinedOutput()

    if ctx.Err() == context.DeadlineExceeded {
        t.Fatalf("subprocess timed out after 30s — likely hanging on fmt.Scanln; the -i10 caller-update may not be short-circuiting before SaveBitString. Output: %s", string(out))
    }

    if err == nil {
        t.Fatalf("expected non-zero exit from subprocess, got nil error; output: %s", string(out))
    }
    if _, isExitErr := err.(*exec.ExitError); !isExitErr {
        t.Fatalf("expected *exec.ExitError, got %T: %v; output: %s", err, err, string(out))
    }

    output := string(out)
    // F-MED-016 (v4.0.2): error message now includes the validation reason
    // returned by ValidatePrivateKey. Pin the prefix portion that's stable
    // across reasons; reason text varies depending on which check fired.
    const wantInvalidPK = "Error: Invalid private key:"
    if !strings.Contains(output, wantInvalidPK) {
        t.Errorf("subprocess output missing %q\n  got: %s", wantInvalidPK, output)
    }
    const wantAbort = "Aborting -i10 base-10 key generation."
    if !strings.Contains(output, wantAbort) {
        t.Errorf("subprocess output missing %q\n  got: %s", wantAbort, output)
    }
}

// TestCLI_SeedWord_TooLong_ExitsWithError is the regression guard for the
// seed-word length validator. Originally guarded Dalos.go's own inline
// check (audit cycle 2026-05-04, F-API-002, which found the error message
// claimed "between 3 and 256" while the check was `< 1 || > 256`). As of
// the 2026-09-11 seed-word-contract hotfix, the CLI no longer runs its
// own check at all — it delegates to the single shared validator,
// Elliptic.ValidateSeedWords (Elliptic/SeedWordsValidation.go), which is
// also what the TS port and any other caller uses. The final contract:
// 1-256 words, each 1-256 glyphs, every glyph in the 256-glyph DALOS
// character set (see README.md's "Personalisable Seed Words" section).
//
// Coverage strategy: drive the rejection branch by passing a single
// 257-glyph word. Asserts (1) non-zero exit, (2) error message reports
// the correct "between 1 and 256 glyphs" bound (catches a future
// regression that re-introduces a wrong bound or byte-vs-glyph miscount).
func TestCLI_SeedWord_TooLong_ExitsWithError(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // -seed reads positional args via flag.Args() AFTER all flags are
    // parsed, so -p must precede the positional seed words.
    // F-MED-004 (v4.0.2): password must be >= 16 chars to satisfy the
    // strength gate. Use 20-char placeholder so we test the seed-word
    // length validator, not the password length.
    longWord := strings.Repeat("a", 257)
    cmd := exec.CommandContext(ctx, "go", "run", ".", "-g", "-seed", "4",
        "-p", "test-password-1234567", longWord, "valid", "more", "words")
    out, err := cmd.CombinedOutput()

    if ctx.Err() == context.DeadlineExceeded {
        t.Fatalf("subprocess timed out after 30s. Output: %s", string(out))
    }
    if err == nil {
        t.Fatalf("expected non-zero exit (seed word too long), got nil; output: %s", string(out))
    }
    if _, isExitErr := err.(*exec.ExitError); !isExitErr {
        t.Fatalf("expected *exec.ExitError, got %T: %v; output: %s", err, err, string(out))
    }

    output := string(out)
    // Pin the correct bound; explicitly forbid the old, wrong "between 3"
    // wording so a future regression that flips it back fails this test.
    const wantCorrect = "expected between 1 and 256 glyphs"
    if !strings.Contains(output, wantCorrect) {
        t.Errorf("subprocess output missing expected wording %q\n  got: %s", wantCorrect, output)
    }
    const forbidWrong = "between 3 and 256"
    if strings.Contains(output, forbidWrong) {
        t.Errorf("subprocess output contains the regressed wrong wording %q\n  got: %s", forbidWrong, output)
    }
}

// TestCLI_GenerateWithoutInputMethod_ExitsWithError is the regression guard
// for the Dalos.go:119 "one input method required" guard. Audit cycle
// 2026-05-04 (F-CRIT-002) found the operators on intaFlag/intbFlag were
// inverted (`!= ""` should be `== ""`), making the guard unreachable for
// the intended case (user supplies -g + -p but no input flag). The bug
// caused `dalos -g -p anything` to silently exit 0 with no key generated.
//
// Fix: invert the two operators. This test asserts the guard now fires:
//
//   1. Subprocess exits non-zero (os.Exit(1) after the diagnostic).
//   2. Combined output contains the canonical error message.
func TestCLI_GenerateWithoutInputMethod_ExitsWithError(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, "go", "run", ".", "-g", "-p", "test")
    out, err := cmd.CombinedOutput()

    if ctx.Err() == context.DeadlineExceeded {
        t.Fatalf("subprocess timed out after 30s — guard at Dalos.go:119 may not be firing; flow probably reached an interactive prompt. Output: %s", string(out))
    }

    if err == nil {
        t.Fatalf("expected non-zero exit from subprocess (the -g-without-input-method guard should fire), got nil; output: %s", string(out))
    }
    if _, isExitErr := err.(*exec.ExitError); !isExitErr {
        t.Fatalf("expected *exec.ExitError, got %T: %v; output: %s", err, err, string(out))
    }

    output := string(out)
    const wantMsg = "Error: One of -raw, -bits, -seed, -i10, or -i49 must be provided when using -g."
    if !strings.Contains(output, wantMsg) {
        t.Errorf("subprocess output missing %q\n  got: %s", wantMsg, output)
    }
}
