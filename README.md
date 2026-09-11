# Ouro-Network Cryptography — DALOS

[![Audit](https://img.shields.io/badge/Audit-Complete-brightgreen)](AUDIT.md)
[![Curve](https://img.shields.io/badge/Curve-verified-brightgreen)](verification/VERIFICATION_LOG.md)
[![Version](https://img.shields.io/badge/Version-4.0.3-blue)](CHANGELOG.md)
[![Phases 0-11 + v4.0.0](https://img.shields.io/badge/Phases%200--11%20%2B%20v4.0.0-COMPLETE-brightgreen)](docs/TS_PORT_PLAN.md)
[![Language](https://img.shields.io/badge/Language-Go%201.22-00ADD8)](go.mod)
[![TypeScript Port](https://img.shields.io/badge/TypeScript%20port-v4.0.3%20on%20npm-brightgreen)](https://www.npmjs.com/package/@ouronet/dalos-crypto)
[![Historical Curves](https://img.shields.io/badge/Historical%20curves-LETO%20%2F%20ARTEMIS%20%2F%20APOLLO%20%E2%9C%93%20production-brightgreen)](docs/HISTORICAL_CURVES.md)

**Ouro-Network Cryptography**, codename **DALOS**, is the cryptographic foundation of the **Ouro-Network Blockchain**. It is built around a custom Twisted Edwards elliptic curve defined over a 1606-bit prime field, supporting **2¹⁶⁰⁰ unique private keys** — vastly more than the 2²⁵⁶ space of traditional blockchains.

This repository is the **canonical Go reference implementation**. The **TypeScript port** in `ts/` is published as [`@ouronet/dalos-crypto`](https://www.npmjs.com/package/@ouronet/dalos-crypto) on npmjs, validated byte-for-byte against this reference on every commit. Additional language ports (Rust, etc.) will follow the same contract.

---

## Status

| Component | Status |
|-----------|--------|
| Curve parameters | ✅ **Mathematically verified** — see [`AUDIT.md`](AUDIT.md) |
| Key-generation pipeline | ✅ Audited — sound, output-frozen |
| Address encoding | ✅ Audited — sound, output-frozen |
| Schnorr signatures | ✅ **v2.0.0 hardened** — all 7 audit items resolved (SC-1 length-prefix, SC-2 deterministic nonces, SC-3 domain tag, SC-4 canonical range, SC-5 on-curve checks, SC-6 error returns, SC-7 constant-time). See [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md) |
| AES key-file encryption | ✅ Audited — AES-256-GCM, Blake3 KDF, findings in [`AUDIT.md`](AUDIT.md#aesaesgo) |
| Test-vector corpus | ✅ **105 vectors** committed — [`testvectors/v1_genesis.json`](testvectors/v1_genesis.json) |
| Blake3 + AES inlined | ✅ Self-contained — no external Go module dependencies |
| **40×40 bitmap input** | ✅ **Added in v1.2.0** — 6th key-gen path, see [`Bitmap/Bitmap.go`](Bitmap/Bitmap.go) |
| **Historical curves** | ✅ **Production-ready as of TS v1.2.0** — LETO / ARTEMIS / APOLLO exposed as full `CryptographicPrimitive` wrappers with their own address prefixes + Schnorr v2 + registry detection. See [`docs/HISTORICAL_CURVES.md`](docs/HISTORICAL_CURVES.md). |
| **TypeScript port** | ✅ **Live on npm** as [`@ouronet/dalos-crypto@3.1.0`](https://www.npmjs.com/package/@ouronet/dalos-crypto) — byte-identical with this Go reference on DALOS Genesis + LETO + ARTEMIS + APOLLO (366/366 tests incl. the 39-test historical-primitive integration suite + 11 alias round-trip + 8 CI-workflow structural). v3.1.0 ships `CHANGELOG.md` in the npm tarball + auto-creates GitHub Releases on tag push (release-engineering hygiene; pattern replicated from sibling project `StoaChain/OuronetCore`). |
| Third-party cryptographic audit | 📋 Recommended before production Schnorr use |

---

## Key Features

### 0. Six key-generation input paths

Ouronet accounts are derived from a 1600-bit private scalar. Any of these six input types reaches the same scalar via deterministic reshaping and/or hashing:

1. **Random** — `crypto/rand` produces 1600 bits
2. **Bitstring** — user-supplied 1600-character `"01…"` string
3. **Integer base 10** — user-supplied big-decimal string (clamped & validated)
4. **Integer base 49** — user-supplied base-49 string (clamped & validated)
5. **Seed words** — arbitrary UTF-8 word list hashed via seven-fold Blake3 into 1600 bits
6. **40 × 40 bitmap** — black/white grid; exactly 1600 pixels = 1600 bits (new in v1.2.0)

All six paths produce bit-for-bit identical output for equivalent inputs. The Genesis key-generation path is permanently frozen at v1.0.0 — adding the bitmap in v1.2.0 is pure input reshaping, not a change to the underlying scalar/curve/address derivation.

### 1. Custom Twisted Edwards Elliptic Curve

The **DALOS Ellipse** (`TEC_S1600_Pr1605p2315_m26`) is a Twisted Edwards curve defined by the equation:

> **x² + y² ≡ 1 − 26·x²·y²  (mod 2¹⁶⁰⁵ + 2315)**

Its mathematical properties — independently verified with both [Python (gmpy2 + sympy)](verification/verify_dalos_curve.py) and [Sage](verification/verify_dalos_curve.sage) — are:

- The prime field `P = 2^1605 + 2315` is prime (1606-bit).
- The base-point order `Q = 2^1603 + K` is prime (1604-bit).
- The generator `G = (2, 4795…7472)` has order exactly `Q` (verified via explicit `[Q]·G = O` computation).
- The cofactor is `R = 4`.
- `d = −26` is a quadratic non-residue mod P, giving the curve a **complete addition law** (Bernstein–Lange) — no exceptional points, no branching.

See [`AUDIT.md § 1`](AUDIT.md#1-mathematical-verification) for full detail and [`verification/VERIFICATION_LOG.md`](verification/VERIFICATION_LOG.md) for verbatim run output.

### 2. Personalisable Seed Words

One of Ouro-Network's signature features: **user-defined seed phrases**,
drawn from DALOS's own 256-glyph character set (the same alphabet used
to render `Ѻ.`/`Σ.` addresses) rather than a fixed word dictionary.

**Final contract (settled 2026-09-11), enforced identically everywhere
in the codebase — the Go reference, the TS port, and therefore the CLI
and every downstream caller — by a single shared validator
(`Elliptic.ValidateSeedWords` / `validateSeedWords`):**

- **1 to 256 words.**
- **1 to 256 glyphs per word.**
- **Every glyph must be one of the 256 characters in the DALOS
  CharacterMatrix** — digits, currency signs, the full Latin alphabet
  plus most Western/Central European diacritics (French, German,
  Spanish, Czech, Polish, Romanian, Croatian, Nordic, Baltic, and more),
  a curated Greek subset, and a curated Cyrillic subset. **This is a
  closed, specific 256-character alphabet, not "any UTF-8 character"** —
  the exact glyphs are enumerated in [`Elliptic/CharacterMatrix.go`](Elliptic/CharacterMatrix.go)
  / [`ts/src/gen1/character-matrix.ts`](ts/src/gen1/character-matrix.ts).
  Two things worth knowing before typing a phrase in Greek or Cyrillic:
  the matrix deliberately **excludes** Greek/Cyrillic letters that are
  visual homoglyphs of Latin letters already in the set (so Cyrillic
  is a ~25-of-33-letter subset, Greek small letters exclude ο/υ, Greek
  capitals exclude every letter that looks Latin), and it has **no
  accented Greek vowels at all** (ά, έ, ή, ί, ό, ύ, ώ — none of these
  are present, only the unaccented forms that survive the homoglyph
  exclusion above). A phrase that uses excluded letters will be rejected; this is
  enforced identically in Go and TypeScript, so what fails on one side
  fails on the other, with the same error.
- **Memorisable** — personalised phrases leverage the brain's natural
  retention of meaningful content, within that alphabet.

**This is deliberately not a BIP-39 mnemonic, and the difference
matters.** BIP-39 requires choosing words from one fixed, English-only
dictionary of ~2048 entries, in a fixed count (12/15/18/21/24), with a
built-in checksum — you cannot type a word that isn't on the list. DALOS
has **no fixed *word* dictionary** — any sequence of glyphs from the
256-character set, up to 256 words, each up to 256 glyphs, is a valid
seed phrase; there is no list of permitted whole words to pick from.
The trade-off for that flexibility is a fixed *character* set instead of
a fixed word list — still categorically more flexible than BIP-39's
closed 2048-word list, just not "arbitrary Unicode."

### 3. Demiourgos Account Structure

Two account types, each a 160-character string (plus symbol prefix):

- **Standard Account** — prefixed `Ѻ.`  Example: `Ѻ.èтďeÏûĂÔЧCιæĂñù…`
- **Smart Account** — prefixed `Σ.`  Example: `Σ.èтďeÏûĂÔЧCιæĂñù…`

Addresses are derived via seven-fold Blake3 hashing followed by mapping through a 16×16 Unicode character matrix spanning Cyrillic, Greek, Latin-extended, accented Latin, currency, and mathematical symbols.

### 4. Deterministic RSA-4096 for Arweave

The same 1600-bit seed that produces a DALOS Genesis EC keypair can also deterministically produce a real, standards-compliant RSA-4096 keypair — the format Arweave wallets require, which cannot be derived from an EC key by conversion (a completely different algebraic structure). `crypto/rsa.GenerateKey` from Go's standard library is permanently unusable for this — its caller-supplied entropy is ignored by default since Go 1.26, and even the escape hatch has a deliberate anti-determinism safeguard baked in since 2018 (`crypto/internal/randutil.MaybeReadByte`, whose own doc comment names "assuming that rsa.GenerateKey is deterministic w.r.t. a given random stream" as the exact thing it exists to prevent) — so this is a from-scratch FIPS 186-5 prime search implemented in both Go (`RSA4096/`) and TypeScript (`ts/src/rsa4096/`), never wrapping a standard RSA generator.

**The process, stage by stage:**

1. **Seed → deterministic byte stream.** The seed bitstring is hashed (as literal ASCII `'0'`/`'1'` bytes) into a Blake3 **XOF** — reusing the same extendable-output primitive already shipped for the EC path rather than introducing a new DRBG, under a dedicated domain tag (`DALOS-gen1/RSA4096Stream/v1`).
2. **Candidate generation.** 256 fresh bytes (2048 bits) off the stream per guess; top two bits forced to `1` (guarantees a true 2048-bit number whose product with another lands at exactly 4096 bits), bottom bit forced to `1` (odd). 2045 of 2048 bits are untouched seed material.
3. **Cheap rejection.** Trial division against the first 2000 odd primes (sieved at call time, not hardcoded — chosen from an explicit cost-model: one division ≈ 32 word-ops, one full primality round ≈ 3.1 million word-ops on a 2048-bit number, and 2000 sits inside the flat optimum of that ~98,000× cost gap).
4. **The real test.** Hand-rolled Miller-Rabin, **100 rounds** (one-time cost per seed, no per-transaction cost to amortize, so no reason not to buy the margin), witnesses drawn from the same seeded stream via **rejection sampling** — not `mod`, which would be measurably biased here (every candidate's forced top bits put `n` in a narrow high range where `n-3` doesn't evenly divide `2^2048`). `math/big.Int.ProbablyPrime` appears only in this package's own tests, as an independent oracle — never on the real generation path.
5. **Safety checks.** `p ≠ q`, `|p-q| > 2^1948` (FIPS 186-5's Fermat-factorization-resistance bound), `gcd(65537, prime-1) = 1` per prime.
6. **Key assembly.** `n = p·q`, `e = 65537` (fixed, universal, never derived from the seed), `d = e⁻¹ mod λ(n)` via the Carmichael function — empirically confirmed (against a real `openssl genrsa 4096` output) to match OpenSSL/WebCrypto convention.
7. **The Arweave-specific step.** Canonical 9-field JWK, address = `Base64URL(SHA-256(n))`, verified directly against `arweave-core`'s own `address.ts`/`keyfile.ts` logic.

**Zero real entropy anywhere in that chain, verified by grepping the whole dependency graph** — this package's own code, the Blake3 package it calls into, and (TS side) `@noble/hashes`'s underlying `blake3`/`sha2` — not asserted from design intent alone.

Validated against real, independent code: the actual `arweave-core` package's `importKeyfile()`/`addressOf()`, and Node's native WebCrypto RSA-PSS sign+verify — not just internal self-checks. Generation is a one-time-per-seed operation (not a per-transaction cost) and exposes a purely-observational progress-reporting API (plus, on the TypeScript side, an event-loop-yielding async variant) so a UI can render a live, mathematically-grounded progress bar during the multi-second search — the completion estimate is a real geometric-distribution CDF (`1-(1-p)^attempts`), not a fake animation. The seed itself isn't hardcoded to DALOS Genesis's 1600 bits — APOLLO's 1024-bit safe-scalar bitstring works too. **The accepted lengths are a closed allow-list, not an open floor:** exactly `1024` or exactly `1600`, nothing else however long (settled 2026-09-11 — an earlier, wider "any length ≥ 128 bits" contract was tightened deliberately). RSA-4096's security comes from the 2048-bit prime search space, not seed length, so a longer or custom-length seed buys nothing; gating to exactly these two lengths ties every RSA seed to one of DALOS_Crypto's two production EC curves' own already-validated input pipelines. See [`.docs/deterministic-rsa4096-from-seed.md`](.docs/deterministic-rsa4096-from-seed.md) for the full design history and empirical research.

---

## Quick Verification

**Anyone can reproduce the mathematical verification in under a minute.**

```bash
# one-time setup
pip install sympy gmpy2

# verify
python verification/verify_dalos_curve.py
```

Expected output: seven `[PASS]` lines in ~1 second total runtime. See the full [`verification/README.md`](verification/README.md).

Or, zero-install: paste [`verification/verify_dalos_curve.sage`](verification/verify_dalos_curve.sage) into https://sagecell.sagemath.org/ and click "Evaluate".

---

## Curve Parameters

```
Name            : TEC_S1600_Pr1605p2315_m26
Equation        : x² + y² ≡ 1 + d·x²·y²  (mod P)
Field P         : 2^1605 + 2315                                   (1606-bit prime)
Subgroup order Q: 2^1603 + 1258387060301909…1380413                (1604-bit prime)
Cofactor R      : 4
Trace T         : −5033548241207638…5519336
Coefficient a   : 1
Coefficient d   : −26                                             (non-square mod P)
Generator G.x   : 2
Generator G.y   : 479577721234741891316129314062096…0907472
Safe scalar     : 1600 bits                                       (≤ log₂(Q) = 1604)
```

Defined in [`Elliptic/Parameters.go`](Elliptic/Parameters.go).

---

## Repository Structure

```
DALOS_Crypto/
├── Auxilliary/                     Helper functions (rune trimming, etc.)
├── Blake3/                         Blake3 XOF (inlined from StoaChain/Blake3)
├── AES/                            AES-256-GCM wrapper (inlined)
├── Bitmap/                         40×40 B/W bitmap input (new v1.2.0)
├── Elliptic/
│   ├── Parameters.go               Ellipse struct + DalosEllipse() + E521Ellipse()
│   ├── PointConverter.go           Coord types + modular arithmetic + conversions
│   ├── PointOperations.go          HWCD addition/doubling/tripling + scalar mult
│   ├── KeyGeneration.go            Key-generation API + 16×16 character matrix + GenerateFromBitmap
│   └── Schnorr.go                  Schnorr sign/verify
├── RSA4096/                         Deterministic RSA-4096 for Arweave (new — see Key Features §4)
├── Dalos.go                        CLI driver (standalone key-gen tool)
├── go.mod                          Go module descriptor
├── verification/                   Reproducible mathematical verification
│   ├── README.md                   How to run the verifiers
│   ├── verify_dalos_curve.py       Python + gmpy2 verifier (7 tests)
│   ├── verify_dalos_curve.sage     Sage verifier (same 7 tests)
│   └── VERIFICATION_LOG.md         Verbatim output of the verification run
├── testvectors/
│   ├── v1_genesis.json             105 reproducible input/output vectors
│   ├── v2_rsa4096.json             3 RSA-4096 seed → JWK + address vectors (new)
│   ├── generator/main.go           Deterministic Go generator
│   └── VALIDATION_LOG.md           go vet + build + determinism proof
├── docs/
│   ├── TS_PORT_PLAN.md             14-phase TypeScript port roadmap
│   └── FUTURE.md                   Deferred R&D (post-quantum, etc.)
├── README.md                       This file
├── AUDIT.md                        Full audit report
├── CHANGELOG.md                    Repo change history
└── LICENSE                         Proprietary licence
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| [`AUDIT.md`](AUDIT.md) | Complete source + mathematical audit (2026-04-23) |
| [`CHANGELOG.md`](CHANGELOG.md) | Repo version history |
| [`docs/DALOS_CRYPTO_GEN1.md`](docs/DALOS_CRYPTO_GEN1.md) | Architectural overview for auditors + downstream implementers |
| [`docs/TS_PORT_PLAN.md`](docs/TS_PORT_PLAN.md) | 14-phase TypeScript port roadmap |
| [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md) | Schnorr v2 signature construction (SC-1…SC-7) |
| [`docs/HISTORICAL_CURVES.md`](docs/HISTORICAL_CURVES.md) | LETO / ARTEMIS / APOLLO — provenance, parameters, audit |
| [`docs/FUTURE.md`](docs/FUTURE.md) | Deferred R&D (post-quantum, Gen-2) |
| [`ts/README.md`](ts/README.md) | TypeScript package consumer guide (also shown on npmjs.com) |
| [`verification/README.md`](verification/README.md) | How to run the math verifiers |
| [`verification/VERIFICATION_LOG.md`](verification/VERIFICATION_LOG.md) | Verbatim output from the verification runs (Genesis + historical curves) |
| [Official Ouro-Network Gitbook](https://demiourgos-holdings-tm.gitbook.io/kadena/ouro-network-cryptography) | High-level cryptography documentation |

---

## Roadmap

### Current state — both sides shipped

- ✅ **v1.0.0 (2026-04-23)** — Go reference audited, curve mathematically verified, 105-vector corpus frozen.
- ✅ **v2.1.0 (2026-04-24)** — Go reference + LETO/ARTEMIS/APOLLO historical curves added (`Elliptic/Parameters.go`). Python 21-test audit on all three curves passing.
- ✅ **TypeScript port v1.1.0** — published to **[npmjs.com/package/@ouronet/dalos-crypto](https://www.npmjs.com/package/@ouronet/dalos-crypto)**. Byte-identity with Go reference proven across 105 test vectors + 20 Schnorr sign+verify + 21 historical-curve math checks.
- ✅ **Ouronet UI** — migrated off `go.ouronetwork.io/api/generate`. All key-gen now happens locally in the browser via the TS port. See Phase 9 of [`docs/TS_PORT_PLAN.md`](docs/TS_PORT_PLAN.md).
- 📋 **Phase 12 (optional)** — retirement of the Go endpoint. Not blocking; keep alive as a fallback as long as useful. Code-side already disconnected.

### Architecture (published npm packages)

```
@stoachain/dalos-blake3      ← Blake3 XOF primitive       (repo: StoaChain/Blake3 — published)
       ↑ depends on
@ouronet/dalos-crypto      ← DALOS Gen-1 + Schnorr + AES (this repo, ts/ subfolder — published)
       ↑ depends on
@ouronet/ouronet-core      ← Pact builders + codex + signing pipeline (repo: StoaChain/OuronetCore — published)
       ↑ depends on
OuronetUI                    ← Browser DEX                (repo: DemiourgosHoldings/OuronetUI)
```

### Design principles (all satisfied at current version)

1. **Bit-identity with Go reference** — every existing Ouronet address stays valid forever. ✅ Enforced by the 105-vector CI test battery.
2. **Modular primitive registry** — Genesis is `DalosGenesis` (`id: "dalos-gen-1"`). Future "Gen 2" can register alongside without breaking Gen 1 users. ✅
3. **Public exposure** — the TypeScript port is published to the public npm registry under `@ouronet/dalos-crypto`. Third parties can consume without auth. ✅
4. **Full test coverage** — 105-vector Go-reference corpus + 20 Schnorr sign-and-verify + 33 historical-curve integrity = **301 tests** passing on every commit. ✅

Plan document: the 14-phase breakdown (Phase 0 = audit, Phase 1 = math foundation, … Phase 12 = retirement of the Go server) lives in [`docs/TS_PORT_PLAN.md`](docs/TS_PORT_PLAN.md) — phases 0–11 are complete.

### Hardening catalogue

**Hardening was performed in the Go reference first**, then preserved byte-for-byte in the TypeScript port. Phase 0 of the TS port plan was explicitly a Go-side hardening pass — all subsequent phases (1–11) port that hardened Go code to TypeScript and verify bit-identical output. The TypeScript port is not where hardening "landed"; the Go reference is.

Category-A fixes (output-preserving) landed in the Go reference:
- ✅ Branch-free base-49 scalar-multiplication (linear scan over precompute matrix)
- ✅ Input validation on all public entry points (explicit errors with reason codes)
- ✅ Explicit error returns throughout

Category-B fixes (Schnorr, output-changing — v2.0.0 of the Schnorr signature format) landed in the Go reference:
- ✅ SC-1 — length-prefixed Fiat–Shamir transcript
- ✅ SC-2 — RFC-6979 deterministic nonces
- ✅ SC-3 — `"DALOS-gen1/SchnorrHash/v1"` + `"DALOS-gen1/SchnorrNonce/v1"` domain-separation tags (see [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md) §3.3)
- ✅ SC-4 — canonical `s` range (reject `s ≥ Q`)
- ✅ SC-5 — on-curve checks on deserialised points
- ✅ SC-6 — structured `VerifyResult` errors, no silent false-true
- ✅ SC-7 — constant-time byte comparisons

**All of the above are preserved in the TypeScript port** (v1.0.0+), validated by the byte-identity CI against the 105-vector Go-reference corpus. Nothing about hardening diverges between the two implementations.

One **TS-only improvement** — strictly additive, not changing wire format:
- The TS port constrains the AES IV's high nibble to be non-zero. This sidesteps a latent round-trip edge case in the Go reference's IV serialisation (a `big.Int → hex → bytes` path that drops the high nibble when it's zero — ≈ 6% of random IVs). Ciphertexts produced by the TS port always decrypt in both TS and Go; Go-produced ciphertexts round-trip correctly in TS as long as their IV landed in the 94% safe range. This is an implementation-level avoidance rather than a spec change.

**TypeScript async surface (since v3.1.0)** — additive browser-friendly path: `scalarMultiplierAsync`, `schnorrSignAsync`, `schnorrVerifyAsync` are exported from `@ouronet/dalos-crypto/gen1`. The synchronous variants block the UI thread for hundreds of milliseconds to seconds at full curve scale; the async variants yield to the event loop every 8 outer-loop iterations on a fixed data-independent cadence and keep INP under 200 ms. Output is byte-identical to the sync variants. See the `### Browser-friendly async signing` section in [`ts/README.md`](ts/README.md) for the consumer snippet.

See [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md) for the full Schnorr v2 spec
and [`AUDIT.md § 3`](AUDIT.md#3-fix-classification) for the finding catalogue that drove the Go-side hardening.

---

## Related Repositories

| Repository | Role |
|------------|------|
| [`StoaChain/DALOS_Crypto`](https://github.com/OuroborosNetwork/dalos-crypto) | **This repo** — Go reference + TypeScript port (`ts/`, published as `@ouronet/dalos-crypto`) |
| [`StoaChain/Blake3`](https://github.com/StoaChain/Blake3) | Blake3 hash function (Go reference; externally validated) |
| [`StoaChain/OuronetCore`](https://github.com/StoaChain/OuronetCore) | TypeScript client SDK — consumes `@ouronet/dalos-crypto` via its `./dalos` subpath since v1.3.0 |
| [`DemiourgosHoldings/OuronetUI`](https://github.com/DemiourgosHoldings/OuronetUI) | Reference web application (Ouronet DEX) — consumes `@ouronet/ouronet-core` |

---

## Security Disclosure

### What has been verified

- Mathematical soundness of all curve parameters (7-test suite, reproducible) — DALOS Genesis + LETO + ARTEMIS + APOLLO
- Correctness of HWCD point-operation formulas against the Explicit-Formulas Database
- Correctness of the base-49 scalar-multiplication path (branch-free linear scan — see Hardening catalogue above)
- Determinism of key-generation pipeline for all valid inputs
- Character matrix has no duplicate runes
- Seven-fold Blake3 construction is cryptographically benign (no attack surface)
- Byte-identity between the Go reference and the TypeScript port — 105-vector corpus + 20 Schnorr sign-and-verify

### Findings catalogue — all resolved

Every finding from the original audit has been addressed in the Go reference (v2.0.0 / v2.1.0) and preserved in the TypeScript port (v1.0.0+). For each item below, the "Status" column points at where the fix lives.

| Original finding | Status |
|---|---|
| Scalar multiplication was non-constant-time | ✅ **Fixed** — branch-free base-49 Horner linear-scan over the precompute matrix. Runtime + memory access pattern independent of the secret digit. |
| Silent error discards in several places | ✅ **Fixed** — explicit error returns / typed errors throughout the Go reference; `throw` with descriptive messages in the TS port. |
| Schnorr hardening items (7 findings) | ✅ **Fixed** — Schnorr v2.0.0 ships SC-1…SC-7 (length-prefixed Fiat–Shamir, RFC-6979 deterministic nonces, `DALOS-gen1/SchnorrHash/v1` + `DALOS-gen1/SchnorrNonce/v1` domain tags, canonical `s ∈ [0,Q)`, on-curve checks, structured errors, constant-time comparisons). See [`docs/SCHNORR_V2_SPEC.md`](docs/SCHNORR_V2_SPEC.md) §3.3 for the canonical tag definitions. |
| AES mode audit pending | ✅ **Resolved** — AES-256-GCM with Blake3 KDF confirmed + documented in [`docs/DALOS_CRYPTO_GEN1.md § 7`](docs/DALOS_CRYPTO_GEN1.md#7-aes-256-gcm-encryption). TS port additionally works around a latent Go-era IV nibble bug (see Hardening catalogue, TS-only improvement). |

Full audit trace lives in [`AUDIT.md`](AUDIT.md). No open findings at v2.1.0 (Go) / v1.1.0 (TS).

### What we recommend before deeper production use

1. **Third-party cryptographic audit** by an accredited firm — a second independent review of the Schnorr v2 construction and the AES-256-GCM integration. Especially valuable if DALOS Schnorr is scheduled for on-chain authentication.
2. **Independent re-run of the verification suite** — on a different OS with a different gmpy2/sympy version — to rule out toolchain peculiarities.
3. **Adversarial test-vector corpus** — edge cases (zero-bitstrings, boundary scalars near Q, invalid points) contributed by external reviewers.

### Responsible disclosure

Found something concerning? Open an issue, or contact the maintainers privately via the StoaChain organisation. Please do not post exploit details publicly before a fix is coordinated.

---

## License

**Proprietary — Copyright © 2026 AncientHoldings GmbH. All rights reserved.** See [`LICENSE`](LICENSE) for full terms.

The licence grants permission to inspect, audit, run the verification scripts, and integrate with sanctioned StoaChain products. Redistribution, derivative works, and commercial use outside the Ouro-Network ecosystem require explicit written permission from AncientHoldings GmbH.

---

## Acknowledgements

- **DALOS author — [Kjrekntolopon](mailto:Kjrekntolopon@ancientholdings.eu)**, Geschäftsführer of AncientHoldings GmbH. Designed the custom 1606-bit Twisted Edwards curve, ran multi-day parallel prime searches on a Ryzen 5950X before AI-assisted development existed, built the full DALOS stack (curve, key generation, Schnorr, seven-fold Blake3, 16×16 character matrix, Demiourgos account structure) from scratch.
- **[hyperelliptic.org/EFD](https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended.html)** — source of the HWCD formulas.
- **Bernstein, Lange, Hisil, Wong, Carter, Dawson** — foundational work on Twisted Edwards curves.
- **The Blake3 team** — spec + reference Go implementation.
- **@noble/hashes** — the spec-compliant TypeScript Blake3 that the forthcoming port will use.

---

*For updates, see [`CHANGELOG.md`](CHANGELOG.md). For the deep technical audit, see [`AUDIT.md`](AUDIT.md).*
