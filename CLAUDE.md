# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## New Claude session? Start here.

This project is linked to **Claudstermind** at `../../Claudstermind/`. Run the cluster-load skill:

> Read `../../Claudstermind/README.md` and load context for this project.

See [`../../Claudstermind/skills/load-cluster.md`](../../Claudstermind/skills/load-cluster.md) for the full procedure. Claudstermind holds this project's onboarding, current state, architecture deep-dive, conventions, and accumulated learnings — always check there before re-briefing Claude.

The knowledge base lives at [`../../Claudstermind/projects/DALOS_Crypto/`](../../Claudstermind/projects/DALOS_Crypto/).

## Cluster context at a glance

DALOS_Crypto is the cryptographic foundation of the Ouro-Network. Every `Ѻ.` / `Σ.` account anywhere in the Ancient-Holdings suite was produced by this code (Go reference) or the `go.ouronetwork.io/api/generate` service running it. Genesis key-gen output is **permanently frozen** at commit `d136e8d` (tag `v1.0.0`); the 105-vector corpus in `testvectors/v1_genesis.json` is the contract every future language port must satisfy byte-for-byte (canonical SHA-256 at v1.2.0: `037ac01a4df6e9113de4ea69d8d4021f5adaa2a821eb697ffe3009997d3c24e9`).

Current state: **Go reference at `v4.0.2`**, **TypeScript port at `@ouronet/dalos-crypto@4.0.2`** on npm — both shipped 2026-05-05 closing audit cycle 2's MEDIUM band (21/21 + 3/3 NEEDS-CONTEXT findings dispositioned; see [`AUDIT.md`](AUDIT.md) "Audit Cycle 2 Close-Out" section). The earlier hardening trajectory: Phase 0c (v1.3.0) = Cat-A batch 1 (constant-time scalar mult + Schnorr verify hardening); Phase 0d (v2.0.0) = Cat-B Schnorr v2 (length-prefix, deterministic nonces, domain tags `DALOS-gen1/SchnorrHash/v1` + `DALOS-gen1/SchnorrNonce/v1`); Phase 0c-finish (v2.1.0) = Cat-A batch 2 (PO-3 noErr helpers, KG-2 error propagation, KG-3 memory hygiene, AES-3 short-circuit); Phase 8-11 (v3.x) = TS port + historical-curves promotion + Phase-11 conformance assertions; v4.0.0 = `keystore` carve-out from `Elliptic/`; v4.0.1 = audit-cycle-2 CRITICAL+HIGH closure (18 findings); v4.0.2 = audit-cycle-2 MEDIUM band closure (15 fixes + 4 architectural-boundary docs + Go 1.19→1.22 toolchain bump). Genesis key-gen output preserved bit-for-bit through every release. 105-vector test corpus (50 bitstring + 15 seed-words + 20 bitmap + 20 Schnorr) plus 60 historical-curve vectors (LETO/ARTEMIS/APOLLO) plus adversarial vectors. CI gates Go (`go-ci.yml`) and TS (`ts-ci.yml` + `ts-publish.yml` matrix Node 20/22/24).

(F-LOW-020, audit cycle 2026-05-04, v4.0.3: this paragraph was previously frozen at v2.1.0 / v1.2.0; updated to current state. Remember to bump after each release commit going forward — `go.mod` and `ts/package.json` are the canonical version sources.)

Claudstermind's KB has the full picture; read it before making changes here.

---

## Two implementations, one contract

This repo houses **both** the canonical Go reference (root) and the published TypeScript port (`ts/`). They are independently buildable but are bound by a single contract: the 105-vector corpus in `testvectors/v1_genesis.json`. Any change in either implementation that perturbs a deterministic vector is a bug — the Genesis key-gen pipeline is frozen forever.

When making changes, always confirm which side you're touching:
- **Go reference** — `Dalos.go` + `Elliptic/`, `AES/`, `Blake3/`, `Bitmap/`, `Auxilliary/`. Module name `DALOS_Crypto`, Go 1.22+ (bumped from 1.19 in v4.0.2 / F-MED-003 — see `go.mod` for rationale), no external deps (Blake3 + AES are inlined).
- **TypeScript port** — everything under `ts/`. Published as `@ouronet/dalos-crypto`. Sole runtime dep is `@noble/hashes` (for Blake3 + RFC-6979 nonces).

The `testvectors/` corpus is the oracle. The Go generator at `testvectors/generator/main.go` is the single producer; the TS test suite is its primary consumer (cross-checks every record against TS-computed output).

---

## Common commands

### Go reference (run from repo root)

```bash
go build ./...                              # compile all packages
go vet ./...                                # static analysis
go run testvectors/generator/main.go        # regenerate testvectors/v1_genesis.json
go run Dalos.go -gd                         # quick demo: generate a random key-pair, print
go run Dalos.go -g -raw -p <password>       # generate + encrypt a wallet file
```

There is no `go test` suite at the root — correctness is validated by re-running the generator and diffing the JSON corpus against the version in git (only the timestamp + 20 Schnorr signatures should vary between runs; all 85 deterministic records must be byte-identical). See `testvectors/VALIDATION_LOG.md` for the canonical procedure and per-release SHA-256s.

### TypeScript port (run from `ts/`)

```bash
npm install
npm test                                    # vitest run — full suite (≈300+ tests, byte-identity vs Go corpus)
npm run test:watch                          # vitest in watch mode
npm test -- <pattern>                       # run a single test file or test name match
npm run typecheck                           # tsc --noEmit
npm run lint                                # biome check src tests
npm run lint:fix                            # biome check --write
npm run build                               # tsc → dist/
npm run clean                               # rimraf dist
```

Node ≥ 20 required. Lint+format is Biome (config in `ts/biome.json`); test runner is Vitest (config in `ts/vitest.config.ts`).

### Curve-parameter math verification (independent of Go/TS)

```bash
pip install sympy gmpy2
python verification/verify_dalos_curve.py   # 7-test suite, ~1s
```

Or paste `verification/verify_dalos_curve.sage` into https://sagecell.sagemath.org/ for a zero-install run. See `verification/VERIFICATION_LOG.md` for verbatim past output.

---

## Architecture

### Go reference layout

| Package | Role |
|---|---|
| `Elliptic/Parameters.go` | `Ellipse` struct + `DalosEllipse()` factory (also `E521Ellipse` and the historical LETO/ARTEMIS/APOLLO factories). The frozen 1606-bit prime, generator, cofactor, safe-scalar bit-width all live here. |
| `Elliptic/PointConverter.go` | `CoordAffine` / `CoordExtended` types + modular arithmetic + affine↔extended conversions. |
| `Elliptic/PointOperations.go` | HWCD (Hisil-Wong-Carter-Dawson) addition/doubling/tripling on extended coords + scalar multiplication. The base-49 path is branch-free (Cat-A hardening). |
| `Elliptic/KeyGeneration.go` | Public key-gen API for all six input modes + the 16×16 Unicode `CharacterMatrix` + Demiourgos address derivation (seven-fold Blake3 → matrix mapping). |
| `Elliptic/Schnorr.go` | Schnorr v2 sign/verify (length-prefixed Fiat-Shamir, RFC-6979 nonces, `DALOS-gen1/SchnorrHash/v1` + `DALOS-gen1/SchnorrNonce/v1` domain tags — see `docs/SCHNORR_V2_SPEC.md` §3.3). |
| `Bitmap/Bitmap.go` | 40×40 B/W bitmap input path (added in v1.2.0). 1600 pixels = 1600 bits, then reshapes into the Genesis bitstring. |
| `Blake3/`, `AES/` | Inlined primitives — Blake3 XOF and AES-256-GCM with Blake3 KDF. No external Go module dependencies. |
| `Auxilliary/Auxilliary.go` | Rune trimming + small helpers. |
| `RSA4096/` | Deterministic RSA-4096 key generation from a DALOS 1600-bit seed bitstring, for Arweave account derivation (`GenerateFromBitString` → JWK + address). A completely different algebraic structure from Gen-1 (no elliptic curve, no `CryptographicPrimitive` registry fit — see `docs/ADDING_NEW_PRIMITIVES.md` Step 8) built from scratch on top of `Blake3` (seed-expansion DRBG) + `math/big` (arithmetic only, never randomness — `crypto/rsa.GenerateKey` is permanently unusable for this, see `.docs/deterministic-rsa4096-from-seed.md` §8). Validated against real `arweave-core` + Node WebCrypto, not just internal self-checks. |
| `Dalos.go` | CLI driver (`-g` generate, `-c` convert, `-open` decrypt wallet, `-sign`, `-verify`, `-gd` demo). |
| `testvectors/generator/main.go` | Reproducible vector generator. Deterministic seeds are `RNG_SEED_BITS = 0xD4105C09702` and `RNG_SEED_BITMAPS = 0xB17A77` — **do not change** without invalidating the corpus. RSA4096 has its own dedicated seed, `RNG_SEED_RSA4096 = 0xC0DE4096`, writing to the separate `testvectors/v2_rsa4096.json` file (never the v1_* files). |

### TypeScript port layout (`ts/src/`)

The TS port mirrors the Go reference's logical decomposition but reorganises it into npm-friendly subpath exports:

| Subpath | Source | Role |
|---|---|---|
| `@ouronet/dalos-crypto` (root) | `src/index.ts` | Re-exports everything for convenience. |
| `/gen1` | `src/gen1/` | Genesis primitive: `curve.ts`, `point-ops.ts`, `scalar-mult.ts`, `key-gen.ts`, `schnorr.ts`, `aes.ts`, `bitmap.ts`, `character-matrix.ts`, `hashing.ts`, `math.ts`, `coords.ts`. |
| `/dalos-blake3` | `src/dalos-blake3/` | Thin wrapper over `@noble/hashes` Blake3 — matches the Go inlined Blake3 byte-for-byte. |
| `/registry` | `src/registry/` | `CryptographicPrimitive` interface + `DalosGenesis` adapter + `CryptographicRegistry` class. The forward-compatibility seam for future Gen-2 primitives (e.g., post-quantum) without breaking existing `Ѻ.`/`Σ.` accounts. |
| `/historical` | `src/historical/` | LETO / ARTEMIS / APOLLO curve params + their primitive registry adapters. **Production-ready as of v1.2.0** — full `CryptographicPrimitive` wrappers with their own address prefixes + Schnorr v2. |
| `/rsa4096` | `src/rsa4096/` | Deterministic RSA-4096 key generation, hand-ported to native `BigInt` (JS has no built-in modexp/gcd/modular-inverse — see `src/rsa4096/bigint-math.ts`). Mirrors `RSA4096/*.go` file-for-file. NOT registered in `/registry`'s `CryptographicPrimitive` interface (that shape is EC-specific: dual addresses, an optional scalar — RSA-4096 has neither). |

Tests under `ts/tests/` mirror this structure. `ts/tests/fixtures.ts` loads the Go-produced corpus and is the source of truth for cross-implementation byte-identity assertions. `ts/tests/rsa4096/rsa4096.test.ts` does the same against `testvectors/v2_rsa4096.json`, asserting every field (p, q, n, d, dp, dq, qi, the full JWK, the address, AND the exact candidate-attempt counts — the strongest possible signal that stream consumption, not just final output, is byte-identical).

### Invariants to preserve

1. **Genesis key-gen output is frozen at v1.0.0.** Any deterministic vector in `v1_genesis.json` must reproduce byte-for-byte. The 50 bitstring + 15 seed-words + 20 bitmap records are the regression frontline. If a change shifts even one byte of any deterministic record, you have a bug — full stop.
2. **Schnorr wire format moved from v1 → v2 in `v2.0.0`.** Pre-v2 Schnorr signatures will not verify under the v2 verifier. The 20 Schnorr vectors in the corpus are already in v2 format; their `r` component is randomised per-run (Go side uses `crypto/rand` for the nonce in some paths) so byte-equality is not asserted on Schnorr — instead, self-verify-true and Go↔TS cross-verify are the assertions.
3. **Go and TS must agree.** Any change to one side's output requires the matching change on the other side, and the corpus must be regenerated and committed atomically. The TS test suite cross-checks against the corpus on every run — drift is caught immediately.
4. **One TS-only deviation, by design.** The TS port constrains the AES IV's high nibble to be non-zero, sidestepping a latent Go-era `big.Int → hex → bytes` round-trip edge case (≈6% failure rate on Go for random IVs). This is implementation-level, not a wire-format change. Documented in README.md "Hardening catalogue".
5. **RSA4096 is a separate primitive, not a Gen-1 extension.** `v2_rsa4096.json` is its own frozen corpus (never a v1_* file); it uses `λ(n)` (Carmichael), not `φ(n)` (Euler), for the private exponent — empirically confirmed to match OpenSSL/WebCrypto in `.docs/deterministic-rsa4096-from-seed.md` §9.2. `MillerRabinRounds` (64) and `SmallPrimeCount` (2000) are exported constants that MUST stay numerically identical between `RSA4096/millerrabin.go` + `RSA4096/primes.go` and `ts/src/rsa4096/millerrabin.ts` + `ts/src/rsa4096/primes.ts` — a mismatch would silently change how many stream bytes get consumed per candidate and break cross-language byte-identity without an obvious error.

### Releases

`CHANGELOG.md` tracks every version, but the load-bearing facts are:
- **v1.0.0** — Genesis frozen.
- **v1.2.0** — Bitmap input added (input reshaping only; Genesis output unchanged). Canonical corpus SHA-256: `037ac01a4df6e9113de4ea69d8d4021f5adaa2a821eb697ffe3009997d3c24e9`.
- **v1.3.0** — Cat-A batch 1 (constant-time scalar mult + Schnorr verify hardening). Output preserved.
- **v2.0.0** — Cat-B Schnorr v2 wire format break.
- **v2.1.0** — Cat-A batch 2 (PO-3, KG-2, KG-3, AES-3). Output preserved. Current head.
- **RSA4096 (2026-09-11)** — new primitive, `testvectors/v2_rsa4096.json` frozen. Deterministic RSA-4096 key generation for Arweave account derivation, Go reference + TypeScript port, validated against real `arweave-core` + Node WebCrypto. Does not touch or supersede any Gen-1 version above — see `.docs/deterministic-rsa4096-from-seed.md` for the full history. (Note: this "Releases" list was already stale relative to the package's actual shipped version — see `go.mod` / `ts/package.json` for the canonical current version — before this entry was added; not resolved here, out of scope.)

Per-release canonical corpus hashes and validation logs live in `testvectors/VALIDATION_LOG.md`.

---

## Adding a new cryptographic primitive

**Read [`docs/ADDING_NEW_PRIMITIVES.md`](docs/ADDING_NEW_PRIMITIVES.md) before touching any code that generates test vectors.** That document is the canonical playbook — TL;DR at the top + step-by-step + troubleshooting. Skipping it almost guarantees you trip the CI byte-identity gate.

The 5 rules in one sentence: never change byte outputs of existing v1 corpus files; new primitives go in NEW corpus files; implement Go AND TypeScript before merging; pin the new corpus's SHA-256 in `.github/workflows/go-ci.yml` when frozen; use the registry pattern for cross-language symmetry.

CI gate added in v4.0.1 (audit cycle 2026-05-04, F-TEST-001): `.github/workflows/go-ci.yml` runs `go build`, `go vet`, `go test`, and the corpus byte-identity check on every push to `main` and every PR touching Go code or test vectors. The byte-identity step regenerates `v1_genesis.json` / `v1_historical.json` / `v1_adversarial.json` and asserts their elided SHA-256 matches the frozen baseline. **Any change that perturbs any existing test vector's output fails this gate.** The playbook explains how to add new primitives without tripping it.

**Adding a primitive with cofactor `h ≠ 4`?** See [`docs/COFACTOR_GENERALIZATION.md`](docs/COFACTOR_GENERALIZATION.md). It covers the small-subgroup attack threat model, the per-cofactor implementation strategy table (h=2/4/8 fast paths + non-power-of-2 fallback), the math for hand-constructing h-torsion adversarial test vectors, and a worked Ed25519 (h=8) example. The Schnorr verifier's cofactor check supports any `h` via dispatch (v4.0.2, F-MED-017) but using a non-h=4 curve requires per-curve threat-model work that the dispatch alone can't do.

---

# BeeDev
Stacks: dalos-go (root, Go reference), dalos-ts (`ts/`, TypeScript port).
Use /bee:new-spec to start a new feature.
Use /bee:progress to see current state.
Always use Context7 MCP for framework documentation lookups.

**Audit-specs lifecycle:** disabled. Do not invoke the user-global `audit-specs-lifecycle` skill in this project. The user manages audit-spec source files manually — do NOT auto-file completed sources to `.bee/audit-specs-done/` after `/bee:archive-spec`.
