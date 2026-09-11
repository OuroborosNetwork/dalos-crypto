package keystore

import (
    el "DALOS_Crypto/Elliptic"
    "bytes"
    "io"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

// bs0001InputBitstring is the 1600-bit deterministic-RNG fixture from the
// frozen Genesis corpus (testvectors/v1_genesis.json, record bs-0001's
// "input_bitstring" field). Duplicated here in Phase 10 (REQ-31, v4.0.0)
// as part of TestExportPrivateKey_FileCreateFailure_*'s relocation from
// Elliptic/KeyGeneration_test.go to this file alongside ExportPrivateKey.
// The original const remains in Elliptic/KeyGeneration_test.go because
// Schnorr_adversarial_test.go in that same package still uses it.
const bs0001InputBitstring = "0010010111000100101111000100101100000000101001110010101110010101010100010011000010000001001001111011011011000100010010001100000110001100001100101011000100000010110000111010011011110010101000010100101011111110110111101111101101101111101011110000110111000110101111000000110110100101100101011001100010010101101110011100001101100011001110110010101000111000000101111011011100100110101101001110110101010001100100100100000111011101011011010101101111110001011011111111111011010000110000111011010001111101100101101111000001010111101110111010101101001101000010001111010010100111000111101001001111111010010101111100100010110001111101111100100100001011100110101011111011101100110111100100110011100010110101011001110000011011110011100000000011111100110101101101010011110011001111001101110011001111011001111111100100011010010000001011000010001010010011010100000011111111000111111100100011001111000101101101110110100111111010010000011101101110001101110101110111101111001110101111110010011000110010101010110010001110011010010111000101100100001011100010101010111011101001111110011100000001101111111110001000001010100000010001000001010111011010001010000011011010100100110111111111111100110110110001011010001001010011001001100001001111101000111000010101000110001100011011111011100001000000111010011010100100101010100101100100111111100100100100101111101000000111111100000000100101100010011101101011011011100011011011011010010000110011001101001100110001000011101000101101011100010100111011100100110000000101101101110101111100101101011011100001000101101101000101111100000000010100010111010101011010110101000111011110001111"

// TestExportPrivateKey_FileCreateFailure_ReturnsError is the behavioural
// regression guard for the F-ERR-005 contract on ExportPrivateKey's
// file-create branch. Pre-v4.0.1 the function discarded write errors
// silently and had no return value; the OpenFile branch printed to
// stdout and returned implicit-nil. Post-v4.0.1 the function returns
// `error`; the OpenFile branch returns a wrapped error AND prints
// (defence-in-depth breadcrumb for CLI users).
//
// Asserts:
//   1. ExportPrivateKey returns a non-nil error.
//   2. The error message wraps the platform's underlying file-system
//      error (so callers can use errors.Is / errors.As on the cause).
//   3. The legacy stdout breadcrumb is still emitted (CLI compatibility).
//
// Phase 10 (REQ-31, v4.0.0): moved verbatim from
// Elliptic/KeyGeneration_test.go alongside ExportPrivateKey.
// v4.0.1 (audit cycle 2026-05-04, F-ERR-005): rewritten to assert the
// returned error in addition to the legacy stdout breadcrumb.
// deriveCorpusFilename recomputes the exact filename ExportPrivateKey will
// target for the bs-0001 corpus fixture -- shared by both tests below so
// each can independently arrange a specific os.OpenFile failure mode at
// that exact path.
func deriveCorpusFilename(t *testing.T) (el.Ellipse, string) {
    t.Helper()
    e := el.DalosEllipse()
    scalar, err := e.GenerateScalarFromBitString(bs0001InputBitstring)
    if err != nil {
        t.Fatalf("GenerateScalarFromBitString rejected the corpus bs-0001 fixture: %v", err)
    }
    keyPair, err := e.ScalarToKeys(scalar)
    if err != nil {
        t.Fatalf("ScalarToKeys rejected the derived scalar: %v", err)
    }
    filename, err := GenerateFilenameFromPublicKey(keyPair.PUBL)
    if err != nil {
        t.Fatalf("GenerateFilenameFromPublicKey rejected the corpus public key %q: %v", keyPair.PUBL, err)
    }
    if filename == "" {
        t.Fatalf("unexpected empty filename from corpus public key %q", keyPair.PUBL)
    }
    return e, filename
}

// captureStdout swaps os.Stdout for a pipe's write end for the duration of
// fn, returning everything written to it. Restores the original os.Stdout
// via t.Cleanup so a panic or t.Fatal inside fn does not leave the test
// runner with a closed/leaked stdout.
func captureStdout(t *testing.T, fn func() error) (error, string) {
    t.Helper()
    origStdout := os.Stdout
    r, w, err := os.Pipe()
    if err != nil {
        t.Fatalf("failed to create stdout-capture pipe: %v", err)
    }
    os.Stdout = w
    t.Cleanup(func() { os.Stdout = origStdout })

    fnErr := fn()

    if err := w.Close(); err != nil {
        t.Fatalf("failed to close pipe write end: %v", err)
    }
    var captured bytes.Buffer
    if _, err := io.Copy(&captured, r); err != nil {
        t.Fatalf("failed to drain pipe read end: %v", err)
    }
    return fnErr, captured.String()
}

// chdirToSandbox chdirs into a fresh t.TempDir() for the duration of the
// test (Go 1.19 lacks t.Chdir), restoring the original cwd via t.Cleanup
// even on t.Fatal. Returns the sandbox's absolute path.
func chdirToSandbox(t *testing.T) string {
    t.Helper()
    originalCwd, err := os.Getwd()
    if err != nil {
        t.Fatalf("failed to capture original cwd: %v", err)
    }
    sandbox := t.TempDir()
    if err := os.Chdir(sandbox); err != nil {
        t.Fatalf("failed to chdir to sandbox %q: %v", sandbox, err)
    }
    t.Cleanup(func() { _ = os.Chdir(originalCwd) })
    return sandbox
}

// TestExportPrivateKey_FileCreateFailure_ReturnsError exercises the
// GENERIC os.OpenFile failure branch (the final `return fmt.Errorf("failed
// to create export file...")` in export.go) -- i.e. a create failure for
// a reason OTHER than the target path already existing.
//
// F-LOW-014 (v4.0.3) history note: this test used to pre-create a
// DIRECTORY at the target path to force a generic os.Create failure
// (EISDIR). That stopped working once F-LOW-014 switched O_TRUNC -> O_EXCL:
// on POSIX, O_EXCL|O_CREAT against ANY pre-existing path -- file or
// directory -- fails with EEXIST, which os.IsExist() now catches FIRST and
// routes to the "already exists" collision-protection branch (see
// TestExportPrivateKey_CollisionProtection_RefusesToOverwrite below), never
// reaching the generic branch this test is actually meant to cover. Fixed
// by triggering a permission failure instead (a read-only target
// directory), which fails at open() for a reason collision-protection
// doesn't intercept -- the file never existed, so os.IsExist(err) is false
// and the generic branch is what actually runs.
func TestExportPrivateKey_FileCreateFailure_ReturnsError(t *testing.T) {
    sandbox := chdirToSandbox(t)
    // The exact filename doesn't matter here -- any create inside
    // `restricted` below fails the same way -- so only `e` is needed.
    e, _ := deriveCorpusFilename(t)

    // Read-only subdirectory: os.OpenFile(..., O_CREATE|...) inside it
    // fails with permission-denied (EACCES), not EEXIST -- the file being
    // created has never existed, so this can't be mistaken for the
    // collision-protection path. Chdir into it so ExportPrivateKey's
    // relative FileName resolves inside the restricted directory.
    restricted := filepath.Join(sandbox, "restricted")
    if err := os.Mkdir(restricted, 0o755); err != nil {
        t.Fatalf("failed to create %q: %v", restricted, err)
    }
    if err := os.Chdir(restricted); err != nil {
        t.Fatalf("failed to chdir to %q: %v", restricted, err)
    }
    // 0o500: read+execute, no write. Removing write permission on the
    // directory itself is what makes creating a NEW entry inside it fail;
    // it does not affect a later rmdir of `restricted` by ITS parent
    // (sandbox), which only requires write permission on sandbox, still
    // 0o755 -- so t.TempDir()'s automatic cleanup is unaffected.
    if err := os.Chmod(restricted, 0o500); err != nil {
        t.Fatalf("failed to chmod %q read-only: %v", restricted, err)
    }
    t.Cleanup(func() { _ = os.Chmod(restricted, 0o755) }) // belt-and-braces for cleanup ordering

    exportErr, output := captureStdout(t, func() error {
        return ExportPrivateKey(&e, bs0001InputBitstring, "test-password")
    })

    // Assertion 1: ExportPrivateKey returns a non-nil error.
    if exportErr == nil {
        t.Fatalf("expected non-nil error from ExportPrivateKey on file-create failure, got nil; stdout: %q", output)
    }
    // Assertion 2: error message mentions the failing operation, and is
    // NOT the collision-protection message (confirms this test actually
    // exercises the generic branch, not F-LOW-014's).
    if !strings.Contains(exportErr.Error(), "failed to create export file") {
        t.Errorf("error message should mention 'failed to create export file'; got: %q", exportErr.Error())
    }
    if strings.Contains(exportErr.Error(), "F-LOW-014") {
        t.Errorf("got the collision-protection error instead of the generic create failure -- got: %q", exportErr.Error())
    }
    // Assertion 3: legacy stdout breadcrumb still emitted for CLI compat.
    const wantSubstring = "Error: failed to create export file:"
    if !strings.Contains(output, wantSubstring) {
        t.Errorf("captured stdout missing legacy breadcrumb\n  want substring: %q\n  got: %q", wantSubstring, output)
    }
}

// TestExportPrivateKey_CollisionProtection_RefusesToOverwrite exercises
// the F-LOW-014 branch specifically: a pre-existing path (file OR
// directory) at the target filename must be refused, not overwritten or
// misreported as a generic create failure. This is the scenario the old
// version of TestExportPrivateKey_FileCreateFailure_ReturnsError
// accidentally started exercising once O_EXCL replaced O_TRUNC (see that
// test's doc comment) -- pulled out into its own explicitly-named test so
// both real failure modes stay covered on purpose, not by accident.
func TestExportPrivateKey_CollisionProtection_RefusesToOverwrite(t *testing.T) {
    sandbox := chdirToSandbox(t)
    e, filename := deriveCorpusFilename(t)

    triggerPath := filepath.Join(sandbox, filename)
    if err := os.MkdirAll(triggerPath, 0o755); err != nil {
        t.Fatalf("failed to pre-create trigger directory at %q: %v", triggerPath, err)
    }

    exportErr, output := captureStdout(t, func() error {
        return ExportPrivateKey(&e, bs0001InputBitstring, "test-password")
    })

    if exportErr == nil {
        t.Fatalf("expected non-nil error when the target path already exists, got nil; stdout: %q", output)
    }
    if !strings.Contains(exportErr.Error(), "F-LOW-014") || !strings.Contains(exportErr.Error(), "already exists") {
        t.Errorf("expected the F-LOW-014 collision-protection error; got: %q", exportErr.Error())
    }
    const wantSubstring = "already exists — refusing to overwrite (F-LOW-014 collision protection)"
    if !strings.Contains(output, wantSubstring) {
        t.Errorf("captured stdout missing collision-protection breadcrumb\n  want substring: %q\n  got: %q", wantSubstring, output)
    }
}
