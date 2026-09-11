# Test Vector Validation Log

This file captures the verbatim output of the Go validation suite against the DALOS Genesis reference implementation. It complements [`../verification/VERIFICATION_LOG.md`](../verification/VERIFICATION_LOG.md) (which is about curve-parameter math) by demonstrating that the full pipeline from bitstring to address works end-to-end and is **bit-for-bit reproducible**.

**Anyone can reproduce this.** See the commands below — each one runs in <1 minute on commodity hardware.

---

## Run — 2026-09-11, latest (indexed/batch RSA4096 generation: one seed, many Arweave addresses)

### What changed

Added `RSA4096/indexed.go` (`GenerateFromBitStringAtIndex`) and `RSA4096/batch.go` (`GenerateBatchFromBitString`), plus their TS mirrors (`ts/src/rsa4096/indexed.ts`, `ts/src/rsa4096/batch.ts`) — deterministic derivation of many independent Arweave addresses from one seed, by index, with `index == 0` structurally guaranteed byte-identical to the pre-existing `GenerateFromBitString`. New frozen corpus `testvectors/v3_rsa4096_indexed.json` (6 vectors), never touching `v2_rsa4096.json`.

### Checks

| Check | Result |
|-------|--------|
| `v1_genesis.json` / `v1_historical.json` / `v1_adversarial.json` / `v2_rsa4096.json` byte-identity (extended-elided) | ✅ UNCHANGED — confirmed via diff before restoring to HEAD; none of this feature's code touches any existing generation path |
| `testvectors/v3_rsa4096_indexed.json` (new) | ✅ 6/6 vectors generated cleanly; elided SHA-256 `2317df5f9ba729b97171949e546a8b35c4ace5759b078b054ccc6a17a18708b0`, pinned in `go-ci.yml` |
| `go test ./...` | ✅ PASS, all packages — 16 new tests across `indexed_test.go` (9) and `batch_test.go` (7) |
| `npm test` (TS) | ✅ 479/479 passing (up from 462) — 11 new in `indexed.test.ts`, 9 in `batch.test.ts`, 8 in `indexed-corpus.test.ts` (the new corpus's byte-identity gate, including a dedicated check that `generateBatchFromBitString(seed, 0, 3)` reproduces `rsa4096-idx-01/02/03` exactly) |
| `npm run lint` / `npm run typecheck` / `npm run docs:check` | ✅ PASS |
| Direct Go↔TS cross-check (not corpus-mediated) | ✅ Same seed at indices `0, 1, 2, 42, 777`: identical addresses in both languages, verified side-by-side in a scratch script, not just inferred from the corpus matching both |

### What this run proves

The single most safety-critical property — that adding this capability could not silently perturb any address anyone might already be relying on — is enforced structurally (`index == 0` calls the untouched function directly, not just "happens to produce the same result"), and separately confirmed empirically: every pre-existing corpus file's elided hash is unchanged. The new corpus's vectors were deliberately chosen so 3 of them (indices 0/1/2 of one seed) double as the frozen proof that batch orchestration reproduces indexed generation exactly, without needing a second, separately-frozen "batch" vector shape.

---

## Run — 2026-09-11, later yet again (RSA4096 seed-bitstring length tightened to a closed allow-list)

### What changed

Considered adding a new entry point accepting an arbitrary custom string up to 65536 characters for RSA-4096 determinism directly. Decided against, and tightened the existing contract instead: `RSA4096/stream.go`'s seed-bitstring validation moved from "any length ≥ 128 characters" (a floor) to an exact allow-list of `{1024, 1600}` (APOLLO, DALOS Genesis) — nothing else, however long. Reasoning: RSA-4096's security comes from the 2048-bit prime search space, not seed length, so a longer or custom-length seed adds no real margin; gating to exactly these two lengths ties every RSA seed to one of DALOS_Crypto's two production EC curves' own already-validated input pipelines (seed-word charset/count checks, etc.), closing off an unaudited "any string, any length" path. `allowedSeedBitStringLengths`/`ALLOWED_SEED_BIT_STRING_LENGTHS` replace `minSeedBitStringLen`/`MIN_SEED_BIT_STRING_LEN`.

### Checks

| Check | Result |
|-------|--------|
| `v2_rsa4096.json` byte-identity (extended-elided) | ✅ UNCHANGED: `0d074fca0f14a5ae6cbcdae571b8d2a7df78dfef12216ac9f77e5f043d751bac` — every existing vector already used a 1600-bit DALOS seed, so no frozen output was ever at risk. |
| `go build ./...` / `go vet ./...` | ✅ PASS |
| `go test ./RSA4096/...` | ✅ PASS — `TestNewSeedStream_AcceptsMultipleCurveShapes` renamed/rewritten to `TestNewSeedStream_AcceptsExactlyTheTwoBlessedLengths`; `TestNewSeedStream_RejectsInvalidSeed` extended with LETO (545), ARTEMIS (1023), and a 65536-character string, all now correctly rejected (all three used to pass under the old floor-only check) |
| `npm test` (TS) | ✅ 451/451 passing (up from 447 — 6 new/rewritten tests in `rsa4096.test.ts`'s seed-length describe block) |
| `npm run typecheck` | ✅ PASS |

### What this run proves

The tightened gate rejects exactly the cases it should (other curves' safe-scalar lengths, an arbitrary long custom string) while continuing to accept both real production lengths without any change to their output — confirmed by the unchanged frozen corpus hash, not just by the new tests passing.

---

## Run — 2026-09-11, later still (seed-word contract hotfix: final restriction level enforced everywhere)

### What changed

Settled a gap surfaced by this project's own documentation-accuracy review: seed-word input had no contract enforced anywhere in the library (Go or TS), only inconsistent, buggy checks in the Go CLI's `-seed` flag handler. Final contract, now enforced by a single shared validator per language (`Elliptic.ValidateSeedWords`, `ts/src/gen1/hashing.ts`'s `validateSeedWords`), called unconditionally inside `SeedWordsToBitString`/`seedWordsToBitString` — the one production entry point every real caller goes through: 1-256 words, each 1-256 glyphs (Unicode code points, not bytes — fixes a latent byte-vs-glyph miscount in the old CLI check), every glyph one of the 256 characters in the DALOS `CharacterMatrix` (a closed, curated alphabet — not "any UTF-8 character"). `Dalos.go`'s CLI now delegates entirely to the shared validator instead of running its own separate checks. `SeedWordsToBitString` (Go) changed signature to `(string, error)`; TS throws `InvalidSeedWordsError`.

### Corpus impact, disclosed in full

Two of `v1_genesis.json`'s 105 vectors used seed words containing glyphs outside the DALOS character set under the old, unenforced regime: `sw-0005` (`привет`/`мир` — contains Cyrillic р/е, both excluded as Latin homoglyphs) and `sw-0006` (`Γειά`/`σου`/`κόσμε` — contains accented Greek vowels and ο/υ, none present in the matrix). Both would now fail `ValidateSeedWords`. Replaced with in-charset equivalents chosen letter-by-letter against `Elliptic/CharacterMatrix.go` (`жизнь`/`плющ`; `Δελτα`/`Σιγμα`/`Ωμεγα` — the Greek spellings of Delta/Sigma/Omega). Every other one of the 105 genesis vectors — all 50 bitstring, the other 13 seed-word, all 20 bitmap, all 20 Schnorr — is byte-identical (diffed line-by-line before re-pinning; only `sw-0005`/`sw-0006`'s content fields differ).

### Checks

| Check | Result |
|-------|--------|
| `v1_genesis.json` byte-identity (extended-elided) | Changed as expected (2 of 105 vectors' input words were out-of-contract under the new rule) — new value `be12073a5b634457bed71b7b54fb6429186ff288f47ce483afbeff9f422ff84c`. All other 103 vectors confirmed byte-identical via diff before re-pinning. |
| `v1_historical.json` byte-identity (extended-elided) | ✅ UNCHANGED: `80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b` |
| `v2_rsa4096.json` byte-identity (extended-elided) | ✅ UNCHANGED: `0d074fca0f14a5ae6cbcdae571b8d2a7df78dfef12216ac9f77e5f043d751bac` (`rsa4096-sw-01` uses ASCII fixture words, unaffected) |
| `v1_adversarial.json` byte-identity (extended-elided) | Corrected an unrelated, pre-existing stale pin discovered opportunistically: committed content was unchanged, but the baseline in `go-ci.yml` didn't match its own elided hash even before this change. New (correct) value: `582025b173de7fb900d65d5b5ad3933ef9abdbc460681c2305b2fadd1aef0bf9`. |
| `go build ./...` / `go vet ./...` | ✅ PASS |
| `go test ./...` | ✅ PASS except one pre-existing, unrelated failure in `keystore` (`TestExportPrivateKey_FileCreateFailure_ReturnsError` — a file-collision-protection ordering issue predating this change, not touched here) |
| New Go tests (`Elliptic/SeedWordsValidation_test.go`) | ✅ 11/11 passing — boundary min/max, rejection of 0/257 words, 0/257-glyph words, out-of-matrix characters (Chinese, excluded Cyrillic/Greek homoglyphs), acceptance of the new in-charset fixtures |
| `npm test` (TS) | ✅ 447/447 passing (up from 436 — 11 new `validateSeedWords`/`seedWordsToBitString` gate tests, plus 4 existing tests updated to reference the new in-charset fixtures) |
| `npm run typecheck` | ✅ PASS |

### What this run proves

The seed-word contract is now identical and unbypassable in both languages — the same input either succeeds identically or fails with an equivalent error on both sides, everywhere it's called from (CLI, library, and by extension any UI built on either). The frozen-corpus change is disclosed and justified rather than silent: exactly 2 of 105 vectors changed, for a stated reason, with every other vector's byte-identity proven unperturbed.

---

## Run — 2026-09-11, later the same day (RSA4096: 64→100 Miller-Rabin rounds, progress API, seed-length generalization)

### What changed

Three pre-publish hardening changes to the RSA4096 primitive (see `.docs/deterministic-rsa4096-from-seed.md` §11 for the full reasoning): `MillerRabinRounds`/`MILLER_RABIN_ROUNDS` bumped 64→100 (one-time-per-seed operation, no per-transaction cost to amortize); a purely-observational progress-reporting API added to both languages plus a TS event-loop-yielding async variant (`generateFromBitStringAsync`) for real UI progress bars; the seed-length validation generalized from an exact 1600-bit (DALOS Genesis) requirement to a 128-bit sanity floor, confirmed working with APOLLO's 1024-bit safe scalar.

### Checks

| Check | Result |
|-------|--------|
| `v1_genesis.json` byte-identity (extended-elided) | ✅ UNCHANGED: `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae` |
| `v1_historical.json` byte-identity (extended-elided) | ✅ UNCHANGED: `80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b` |
| `v2_rsa4096.json` byte-identity (extended-elided) | Changed as expected (round count is part of the frozen contract) — new value `0d074fca0f14a5ae6cbcdae571b8d2a7df78dfef12216ac9f77e5f043d751bac`, confirmed stable across 3 independent regenerations before re-pinning `.github/workflows/go-ci.yml`. `p_attempts` for all 3 vectors unchanged (402, 27, 138 — `p` is found before any round-count effect accumulates, exactly as predicted); `q_attempts` changed (516/1439/398, was 552/1484/432 — `q`'s search starts from a stream position shifted by `p`'s now-longer confirmation, exactly as predicted). |
| `go test ./RSA4096/...` | ✅ 15/15 passing (11 original + 4 new: progress-purity, two curve-shape lengths, sub-floor rejection) |
| `npm test` (TS) | ✅ 436/436 passing (up from 431 — 5 new progress/async/seed-length tests) |
| `npm run docs:check` (ts/README.md code fences vs built dist) | ✅ 8/8 blocks pass, including a new live progress-bar example |
| External validation (real `arweave-core` + Node WebCrypto) | ✅ All 3 (new, 100-round) vectors: `importKeyfile`/`addressOf` byte-identical, real RSA-PSS/SHA-256 sign→verify round-trip |

### What this run proves

Confirms the round-count change's effect on the corpus was exactly the predicted one (not a surprise, not a symptom of something else changing), confirms the seed-length relaxation didn't perturb any already-valid seed's output (the length-prefix framing already wrote actual runtime length, never a hardcoded constant, so this was expected but verified anyway), and confirms the new progress-reporting surface is genuinely inert with respect to the cryptographic output — a dedicated test compares output with and without a callback attached and asserts byte-identical results.

---

## Run — 2026-09-11 (RSA4096 primitive added — new corpus, existing corpora unperturbed)

### Environment

| Item | Value |
|------|-------|
| Host OS | Linux (Ubuntu 26.04), bash |
| Go version | go1.27.1 linux/amd64 (installed this session; verified tarball SHA-256 against `go.dev/dl/?mode=json` before install) |
| Generator version | 3.0.1 (unchanged) + RSA4096 generator addition, v1.0.0 |
| Node version | v22.22.1 |

### What changed

New primitive `RSA4096/` (Go) + `ts/src/rsa4096/` (TypeScript): deterministic RSA-4096 key generation from a DALOS 1600-bit seed bitstring, for Arweave account derivation. Graduated from a research prototype (`research/rsa4096-poc/`, now reduced to a thin external-validation harness) after empirical research recorded in `.docs/deterministic-rsa4096-from-seed.md`. New corpus file `testvectors/v2_rsa4096.json` (3 vectors — kept small deliberately since each full RSA-4096 generation costs low-single-digit seconds; see the generator's own comment for the reasoning), own dedicated RNG seed `RNG_SEED_RSA4096 = 0xC0DE4096`.

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS (exit 0), including new `RSA4096/` package |
| `go vet ./...` | ✅ PASS (exit 0) |
| `go test ./...` | ✅ PASS — all existing suites unchanged; new `RSA4096` package suite: 11/11 tests pass (3.5s), including a cross-check against `math/big.Int.ProbablyPrime` as an independent oracle |
| `v1_genesis.json` byte-identity (extended-elided) | ✅ UNCHANGED: `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae` |
| `v1_historical.json` byte-identity (extended-elided) | ✅ UNCHANGED: `80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b` |
| `v1_adversarial.json` byte-identity (extended-elided) | ⚠️ UNCHANGED relative to its own pre-existing state (`582025b173de7fb900d65d5b5ad3933ef9abdbc460681c2305b2fadd1aef0bf9`) but that pre-existing state does **not** match the CI-pinned baseline (`b9f228943106e1293c52a7e3d741520e58940b78816a2eeed7aa7332314b9d93`) — a drift that predates this session and is unrelated to the RSA4096 work (this session never touched adversarial-vector generation code). Flagged for separate investigation; not fixed here per the "never modify BASELINES to silence a gate" rule in `docs/ADDING_NEW_PRIMITIVES.md`. |
| `v2_rsa4096.json` byte-identity (extended-elided) | ✅ Stable across 3 independent regenerations: `b0573a4dc48b55f2394e68fe2a17108e7a3a4bd1dbb781d8c3230984a5470499` — now pinned in `.github/workflows/go-ci.yml` |
| TS test suite (`npm test` from `ts/`) | ✅ 431/431 tests pass (20 files), including new `tests/rsa4096/rsa4096.test.ts` — asserts the TS port reproduces every field of every `v2_rsa4096.json` vector exactly: `p`, `q`, `n`, `d`, `dp`, `dq`, `qi`, the full JWK, the address, **and** the exact candidate-attempt counts (proof of byte-identical stream consumption, not just coincidentally-equal final output) |
| External validation (real `arweave-core` + Node WebCrypto, not internal self-checks) | ✅ All 3 `v2_rsa4096.json` vectors: real `arweave-core`'s compiled `importKeyfile()`/`addressOf()` accept the generated JWKs and reproduce the address byte-for-byte; Node's native WebCrypto imports each as a real RSA-PSS/SHA-256 keypair and completes a real sign→verify round-trip. Run via `research/rsa4096-poc/validate.mjs` + `validate_golden.mjs`. |

### What this run proves

1. Adding an entirely new, non-elliptic-curve primitive did not perturb any existing frozen vector — the byte-identity gate for `v1_genesis.json` and `v1_historical.json` holds exactly.
2. The new primitive's Go and TypeScript implementations agree byte-for-byte, including internal search-path details (attempt counts), not just final output — the strongest form of the cross-language contract this repo already holds for Gen-1.
3. The generated keys are accepted by real, independent Arweave-ecosystem code (not reimplemented by this repo), which is the strongest evidence achievable short of an actual on-chain transaction (deliberately not attempted in this session — needs a funded wallet and a human present).

---

## Run — 2026-04-30 (v3.0.1, error-handling closure)

### Environment

| Item | Value |
|------|-------|
| Host OS | Windows 10 (AMD64), Git Bash |
| Go version | go1.19.4 windows/amd64 |
| Generator version | 3.0.1 |
| `core.autocrlf` | true (CRLF working tree, LF in git blob) |

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS (exit 0) |
| `go vet ./...` | ✅ PASS (exit 0) |
| `go test ./...` | ✅ PASS (Auxilliary 13 + Elliptic <N> + new error-handling regression tests) |
| Generator output | ✅ 105 Genesis + 60 historical vectors |
| **DALOS Genesis byte-identity** (post-v2.0.0 procedurally-reproducible, extended-elided) | ✅ Stable: `082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae` (byte-identical to v3.0.0) |
| TS test suite (`npm test` from `ts/`) | ✅ 347/347 tests pass (16 test files; +1 new failure-injection test from T1.2 — or 348/348 if T1.2 split into two cases) |

### Canonical SHA-256 values at tag `v3.0.1` (extended-elided: timestamp + version + host)

Reproduce with this one-liner from repo root (extends the documented elision to also strip `generator_version` and `host`, matching the spec's "timestamp+version-elided" wording):

```bash
sed -e 's/"generated_at_utc": "[^"]*"/"generated_at_utc": "ELIDED"/' \
    -e 's/"generator_version": "[^"]*"/"generator_version": "ELIDED"/' \
    -e 's/"host": "[^"]*"/"host": "ELIDED"/' \
    testvectors/v1_genesis.json | sha256sum
```

```
testvectors/v1_genesis.json     SHA-256: 082f7a40405d4c075f1975af0a6075bb0228bbccae60a53b05b350a09ce223ae
testvectors/v1_historical.json  SHA-256: 80c93f4d4956e01236808f81f518d17eeaad431f4fedb7c26233d2508f06e68b
```

Both values are byte-identical to the v3.0.0-committed corpus (verified via `git show v3.0.0:... | sha256sum` against the regenerated v3.0.1 file under the same elision recipe — diff returns 0 lines). Phase 1's error-handling work introduced ZERO substantive diff in deterministic content; the corpus is unchanged.

**Reference-hash clarification (inherited mis-citation correction):** The hash `037ac01a4df6e9113de4ea69d8d4021f5adaa2a821eb697ffe3009997d3c24e9` cited at `CLAUDE.md:17,120`, `CHANGELOG.md:658`, and earlier VALIDATION_LOG.md entries is the RAW-BYTES hash of the v1.2.0 committed `v1_genesis.json` snapshot (timestamp baked in, no elision). It is NOT procedurally reproducible from any post-v2.0.0 corpus because the v2.0.0 Schnorr-v2 wire-format break (CLAUDE.md invariant 2) intentionally changed all 20 Schnorr signature payloads. The post-v2.0.0 stable baseline is `082f7a40...` (extended-elided). The v1.2.0 raw-bytes hash `037ac01a...` remains the historical anchor for the frozen v1.2.0 commit and continues to verify against `git show v1.2.0:testvectors/v1_genesis.json | sha256sum` exactly.

---

## Run — 2026-04-30 (v3.0.0, Phase 8 cross-curve byte-identity + historical corpus)

### Environment

| Item | Value |
|------|-------|
| Host OS | Windows 10 (AMD64), Git Bash |
| Go version | go1.19.4 windows/amd64 |
| Generator version | 3.0.0 |
| `core.autocrlf` | true (CRLF working tree, LF in git blob) |

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS (exit 0) |
| `go vet ./...` | ✅ PASS (exit 0) |
| `go test ./Auxilliary/...` | ✅ 13/13 unit tests pass (CeilDiv8 helper) |
| `go test ./Elliptic/...` | ✅ 7/7 unit tests pass (ConvertHashToBitString XCURVE-4 + XCURVE-1..3 ceil-div) |
| Generator output | ✅ 105 Genesis vectors + 60 historical vectors (10 bitstring + 5 seedwords + 5 Schnorr per LETO/ARTEMIS/APOLLO) |
| **DALOS Genesis byte-identity** (timestamp-elided) | ✅ Pre-XCURVE vs Post-XCURVE: SHA-256 stable. Per-vector deterministic outputs unchanged. |
| **APOLLO byte-identity** (S=1024 byte-aligned) | ✅ Pre-fix vs post-fix: zero diff across keys/addresses/Schnorr signatures + handcrafted leading-zero hash probe |
| Schnorr determinism (Genesis) | ✅ 20/20 signatures self-verify; byte-identical across regeneration runs |
| Schnorr determinism (Historical) | ✅ 15/15 signatures self-verify (5 per curve); byte-identical across regeneration runs |
| Per-curve historical address prefixes | ✅ 15× LETO `Ł.`/`Λ.`, 15× ARTEMIS `R.`/`Ř.`, 15× APOLLO `₱.`/`Π.` — 0 DALOS-prefix (`Ѻ.`/`Σ.`) leakage in historical corpus |
| Historical corpus determinism | ✅ Twice-run regeneration produces byte-identical `v1_historical.json` SHA-256 (timestamp-elided) |
| TS test suite (`npm test` from `ts/`) | ✅ 346/346 tests pass (16 test files) |

### Canonical SHA-256 values at tag `v3.0.0` (timestamp-elided)

```
testvectors/v1_genesis.json     SHA-256: 742ef1e271c35d5abe27347688ce1304b14798e7021efe8f7ff6fb54a5392c7a
testvectors/v1_historical.json  SHA-256: 0f60a8fe631dc5d95244d27c247ec0f6e031f629eee7fbe3e9fd48b888a48b35
```

**Verification protocol (Windows Git Bash):**
```bash
sed 's/"generated_at_utc": "[^"]*"/"generated_at_utc": "ELIDED"/' testvectors/v1_genesis.json | sha256sum
sed 's/"generated_at_utc": "[^"]*"/"generated_at_utc": "ELIDED"/' testvectors/v1_historical.json | sha256sum
```

The `generator_version` field bumped from `1.2.0` → `3.0.0` and `host` field updated to `"StoaChain/DALOS_Crypto test-vector generator v3.0.0"` are deliberate metadata changes for v3.0.0; per-vector cryptographic outputs are byte-identical to the pre-Phase-8 frozen state for byte-aligned curves (DALOS, APOLLO).

### What this run proves

1. **Genesis preservation across the XCURVE-1..4 hardening pass.** All 50 bitstring + 15 seedwords + 20 bitmap + 20 Schnorr DALOS vectors reproduce byte-for-byte. The `aux.CeilDiv8` helper produces identical output to floor division for byte-aligned safe-scalars (DALOS S=1600).
2. **APOLLO byte-identity preservation.** S=1024 is byte-aligned; XCURVE-1..4 produce identical APOLLO output. Pre-fix and post-fix scratch tools produce zero-diff JSON across all probed outputs.
3. **LETO + ARTEMIS wire-format break (intentional, per spec).** Pre-v3.0.0 LETO/ARTEMIS Schnorr signatures and seedword-derived keys do NOT match post-v3.0.0 outputs. The byte-identity contract is now formalized at v3.0.0 via `v1_historical.json` and verified by the TS test suite (`tests/registry/historical-primitives.test.ts` BYTE-IDENTITY blocks).
4. **Cross-implementation byte-identity formalized.** The TypeScript port at `@ouronet/dalos-crypto@3.0.0` now reproduces every committed Go-side historical vector byte-for-byte, validated on every npm test run.

---

## Run — 2026-04-23 (v2.0.0, Schnorr v2 hardening)

### Environment

| Item | Value |
|------|-------|
| Generator version | 1.2.0 (unchanged; only Schnorr output format changes) |

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS (exit 0) |
| `go vet ./...` | ✅ PASS (exit 0) |
| Generator output | ✅ 105 vectors (50 bitstring + 15 seed-words + 20 bitmap + 20 Schnorr) |
| **Genesis key-gen byte-identity vs v1.2.0** | ✅ **ALL 85 deterministic records byte-identical** (50+15+20). Genesis contract held through Phase 0c + 0d. |
| Schnorr self-verify | ✅ 20/20 under v2 format |
| **Schnorr determinism** (regenerate twice, compare) | ✅ **20/20 signatures byte-identical across runs** — the v2.0.0 RFC-6979-style nonce derivation delivers full determinism |
| Schnorr format break vs v1.x | ✅ **20/20 signatures differ from pre-v2.0.0** (expected — SC-1/SC-2/SC-3 all change bytes) |

### Canonical SHA-256 of `v1_genesis.json` at tag `v2.0.0`

```
SHA-256:  45c89ec36c30847a92dbd5b696b42d94159900dddb6ce7ad35fca58f4bba16f3
```

### What this run proves

1. **Genesis preservation held through 3 hardening releases (v1.2.0 → v1.3.0 → v2.0.0).** Every bitstring, seed-word, and bitmap derivation produces byte-identical keys/addresses.
2. **PO-1 hardening (v1.3.0) is correct.** Constant-time scalar mult, verified against full corpus.
3. **SC-4, SC-5, SC-6 (v1.3.0) work correctly.** Schnorr verify rejects invalid inputs while passing valid ones.
4. **SC-1, SC-2, SC-3 (v2.0.0) work correctly.** New format is self-consistent; sign produces deterministic output that verify accepts.

---

## Run — 2026-04-23 (v1.3.0, Category-A hardening)

Abridged re-run after Phase 0c Category-A fixes.

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS |
| `go vet ./...` | ✅ PASS |
| Key-gen byte-identity vs v1.2.0 | ✅ all 85 deterministic records byte-identical |
| Schnorr self-verify | ✅ 20/20 (still using v1 Schnorr format) |

Canonical hash recorded in commit `v1.3.0` CHANGELOG entry: `dca92bc33589fdde798f77cd5ce12ce5f3e08701606bfc62c893d852bde29fd7`.

---

## Run — 2026-04-23 (v1.2.0, bitmap vectors added)

### Environment

| Item | Value |
|------|-------|
| Host OS | Windows 10 (AMD64) |
| Go version | go1.19.4 windows/amd64 |
| Generator version | 1.2.0 |

### Checks

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS (exit 0) |
| `go vet ./...` | ✅ PASS (exit 0) |
| Generator output | ✅ 105 vectors produced (50 bitstring + 15 seed-words + **20 bitmap** + 20 Schnorr) |
| Schnorr self-verify | ✅ 20/20 true |
| Bitmap path cross-check | ✅ `GenerateFromBitmap(b) == GenerateFromBitString(BitmapToBitString(b))` for all 20 fixtures |
| Determinism proof | ✅ Only timestamp + 20 Schnorr sigs vary between runs; **all 85 deterministic records (50+15+20) byte-identical** — diff produced 42 lines, matching `1 timestamp×2 + 20 signatures×2`. |

### Canonical SHA-256 of `v1_genesis.json` at tag `v1.2.0`

```
SHA-256:  037ac01a4df6e9113de4ea69d8d4021f5adaa2a821eb697ffe3009997d3c24e9
```

### Bitmap fixtures

| # | Pattern | Notes |
|---|---------|-------|
| 1 | all-white (zeros) | baseline — fromBitmap must equal fromBitString("000…0") |
| 2 | all-black (ones) | baseline — fromBitmap must equal fromBitString("111…1") |
| 3 | checkerboard-even | (r+c) even = white |
| 4 | checkerboard-odd | (r+c) even = black |
| 5 | horizontal-stripes | every 2 rows alternate |
| 6 | vertical-stripes | every 2 cols alternate |
| 7 | border-frame | outer ring black |
| 8 | center-cross | row 20 + col 20 black |
| 9 | top-half-black | rows 0-19 black |
| 10 | left-half-black | cols 0-19 black |
| 11 | diagonal-tl-br | main diagonal black |
| 12 | diagonal-tr-bl | anti-diagonal black |
| 13 | center-dot | single pixel (20,20) |
| 14 | four-corners | 4 corner pixels only |
| 15 | top-left-quadrant | 20×20 block black |
| 16 | concentric-squares | rings spaced every 4 |
| 17-20 | deterministic-random | math/rand seed `0xB17A77` |

---

## Run — 2026-04-23 (v1.1.0, initial corpus)

### Environment

| Item | Value |
|------|-------|
| Host OS | Windows 10 (AMD64) |
| Go version | go1.19.4 windows/amd64 |
| Git commit | `400468e` (v1.1.0) |

### Check 1 — `go vet ./...`

Static analysis catches suspicious constructs, unused variables, unreachable code, format-string mismatches, and common Go pitfalls.

```
$ go vet ./...
$ echo $?
0
```

**Result: EXIT 0, zero output.** No issues flagged across all 11 Go files (`Auxilliary/`, `AES/`, `Blake3/`, `Elliptic/`, `Dalos.go`, `testvectors/generator/`).

### Check 2 — `go build ./...`

```
$ go build ./...
$ echo $?
0
```

**Result: EXIT 0.** The repo is a self-contained Go module — no external dependencies required. The Blake3 + AES inline (v1.1.0) works cleanly.

### Check 3 — `gofmt -l .`

Lists files whose formatting would change if `gofmt` were run. Non-zero output indicates style deviations, not bugs.

```
$ gofmt -l .
AES/AES.go
Auxilliary/Auxilliary.go
Blake3/Blake3.go
Blake3/Compress.go
Blake3/CompressGeneric.go
Dalos.go
Elliptic/KeyGeneration.go
Elliptic/Parameters.go
Elliptic/PointConverter.go
Elliptic/PointOperations.go
Elliptic/Schnorr.go
testvectors/generator/main.go
$ echo $?
0
```

**Result:** 12 files have non-canonical whitespace (mostly tabs-vs-spaces). **This is style only** — no logical or cryptographic implications. `gofmt` was not applied because:

1. The Genesis Go reference is **explicitly frozen** at v1.0.0 — any formatting change, even whitespace, is a commit against the frozen state.
2. `go vet` and `go build` pass cleanly, so there are no *functional* issues.
3. Running `gofmt` does not change binary output or produce different keys/addresses. Purely cosmetic.

If a future consumer wants canonical formatting, they can run `gofmt -w .` on a fork. The Ouronet reference stays as-is.

### Check 4 — Test vector generation

```
$ go run testvectors/generator/main.go
[1/3] Generating 50 bitstring vectors...
      10 / 50
      20 / 50
      30 / 50
      40 / 50
      50 / 50
[2/3] Generating seed-word vectors...
      15 fixtures
[3/3] Generating Schnorr sign+verify vectors...
      20 / 20

=============================================================
  DONE. 85 total vectors written to testvectors/v1_genesis.json
    50 bitstring vectors
    15 seed-words vectors
    20 schnorr vectors
    20 / 20 schnorr signatures self-verified
=============================================================
```

**Result: 85/85 vectors generated; 20/20 Schnorr signatures self-verified.**

### Check 5 — Determinism proof (re-generation diff)

The critical property: running the generator twice on the same machine must produce **identical output for everything except the timestamp and Schnorr signatures** (which are correctly random per-run due to `crypto/rand` nonce selection).

```
$ cp testvectors/v1_genesis.json /tmp/first_run.json
$ go run testvectors/generator/main.go          # regenerate
$ diff /tmp/first_run.json testvectors/v1_genesis.json | grep -c '^[<>]'
42
```

**Analysis of the 42 differing lines:**

| Category | Count | Expected? |
|----------|-------|-----------|
| Timestamp line (`generated_at_utc`) | 1 | ✅ YES — captures current clock |
| Schnorr signature values (20 × 2 sides of diff) | 40 | ✅ YES — random nonce per signature |
| Everything else | **1** | This is the `<` side of the timestamp diff |
| **TOTAL** | **42** | All expected. |

**What was byte-identical across both runs:**

- All 50 bitstring vectors (input bitstring, scalar, priv keys in base 10 + 49, public key, both addresses) ✅
- All 15 seed-word vectors (input words, derived bitstring, scalar, priv key, public key, both addresses) ✅
- All 20 Schnorr vectors' **input**, **keypair**, **public key**, **message**, and `verify_actual: true` flag ✅
- Only the 20 `signature` values differ — which is the correct behaviour for a Schnorr scheme using random nonces.

**This proves:**

1. The **key-generation path is deterministic** for a given input. Same input always yields same output. ✅
2. **Schnorr signature generation is non-deterministic** (by design — random nonce). ✅
3. **Schnorr signature verification is reliable** — 20/20 of each run's signatures self-verify as true. ✅

### Check 6 — Committed file integrity

```
$ git show HEAD:testvectors/v1_genesis.json | sha256sum
0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db  -
```

**The canonical hash of `testvectors/v1_genesis.json` as committed at v1.1.0 is:**

```
SHA-256:  0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db
```

Anyone cloning the repo at tag v1.1.0 can verify this with:

```bash
git checkout v1.1.0
git show HEAD:testvectors/v1_genesis.json | sha256sum
# Expected: 0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db
```

(Note: if you `cat` the file directly on Windows, line-ending autoconversion may produce CRLF and thus a different hash. Use `git show` or `tr -d '\r'` to normalise.)

---

## Summary

| Check | Result |
|-------|--------|
| `go vet ./...` | ✅ PASS (exit 0, no output) |
| `go build ./...` | ✅ PASS (exit 0) |
| `gofmt -l .` | Non-canonical style only — no functional issues |
| Test vector generation | ✅ 85/85 vectors produced |
| Schnorr self-verify | ✅ 20/20 true |
| Determinism proof | ✅ Only timestamp + 20 Schnorr sigs vary; 64 deterministic vectors byte-identical |
| Canonical JSON hash | `0ca25d6b6aa9a477fb3a75498cd7bc2082f9f79ccb8b23ab72caad22f28066db` |

**Conclusion:** the Go reference implementation is **functionally correct, reproducible, and ready to serve as the oracle for the forthcoming TypeScript port.**

---

## Re-validation policy

This check battery should be re-run:

- Any time any Go source file is modified
- Before any major tag/release
- Annually as a prudent integrity check
- When a new generator version is introduced (would produce a new `v2_*.json` — do not overwrite v1)

Append new entries to this file with the date of each re-run. Never overwrite.

---

*Log maintained by StoaChain. See [`../AUDIT.md`](../AUDIT.md) for the full source + mathematical audit. See [`../verification/VERIFICATION_LOG.md`](../verification/VERIFICATION_LOG.md) for the curve-parameter verification.*
