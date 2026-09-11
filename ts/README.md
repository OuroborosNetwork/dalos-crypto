# @ouronet/dalos-crypto

> TypeScript port of the DALOS Genesis cryptographic primitive — Ouronet's
> custom 1606-bit Twisted Edwards curve with six key-generation input
> paths, Schnorr v2 signatures, AES-256-GCM encryption, a pluggable
> `CryptographicRegistry` for multi-generation forward compatibility, and
> deterministic RSA-4096 key generation for Arweave accounts from the
> same custom seed phrase.

[![npm](https://img.shields.io/npm/v/@ouronet/dalos-crypto.svg)](https://www.npmjs.com/package/@ouronet/dalos-crypto)
[![tests](https://img.shields.io/badge/tests-431%20passing-brightgreen.svg)](#verification)
[![license](https://img.shields.io/badge/license-UNLICENSED-blue.svg)](https://github.com/StoaChain/DALOS_Crypto)

---

## Install

```bash
npm install @ouronet/dalos-crypto
# or
yarn add @ouronet/dalos-crypto
```

Requires **Node ≥ 20** (uses native `BigInt` + `globalThis.crypto.getRandomValues`).
Runs in the browser without polyfills on any modern evergreen target.

> **ESM-only.** This package ships as a pure ES module (`"type": "module"` +
> ESM-only `exports` conditions). CommonJS consumers using `require()` will
> hit `ERR_REQUIRE_ESM`. Use `import` syntax with Node ≥ 20, a bundler
> (Vite, esbuild, Webpack 5+, Rollup), or dynamic `import()` from CommonJS.

---

## What you get

### Genesis curve — `DALOS_ELLIPSE`

A custom Twisted Edwards curve over `P = 2^1605 + 2315` (a 1606-bit
prime), with safe-scalar bit width **S = 1600**. Private key space =
**2¹⁶⁰⁰ ≈ 4 × 10⁴⁸¹** — roughly 10⁴⁰⁴ × larger than Bitcoin's.

| Parameter | Value |
|---|---|
| Name | `TEC_S1600_Pr1605p2315_m26` |
| Field prime `P` | `2^1605 + 2315` (1606-bit) |
| Subgroup order `Q` | `2^1603 + 1258387…1380413` (1604-bit prime) |
| Cofactor `R` | `4` |
| Coefficients `(a, d)` | `(1, -26)` |
| Generator `G` | `(2, 479577…907472)` |
| Safe scalar `S` | 1600 bits |

Independently audited and verified — see the main repo's
[`AUDIT.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/AUDIT.md)
and [`verification/VERIFICATION_LOG.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/verification/VERIFICATION_LOG.md).

### Six key-generation input paths — one scalar

All six paths produce **byte-for-byte identical** output with the Go
reference's [105-vector test corpus](https://github.com/StoaChain/DALOS_Crypto/blob/main/testvectors/v1_genesis.json).

| Mode | Input | Typical use |
|---|---|---|
| `random` | OS randomness | one-click account spawning |
| `bitString` | 1600-bit `0`/`1` string | research, direct scalar, paper wallets |
| `integerBase10` | decimal integer (< Q) | numeric private keys |
| `integerBase49` | base-49 string (< Q) | DALOS-native compact integer form |
| `seedWords` | array of UTF-8 words | BIP-39-style mnemonics (12 / 24 / 4–256 custom) |
| `bitmap` | 40×40 `Bitmap` | hand-painted entropy (1600 pixels = 1600 bits) |

### Schnorr v2 signatures

Full hardened Schnorr implementation with RFC-6979-style deterministic
nonces (Blake3-tagged KDF), length-prefixed Fiat-Shamir challenge, and
domain-tag separation.
See [`docs/SCHNORR_V2_SPEC.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/SCHNORR_V2_SPEC.md).

### AES-256-GCM with Blake3 KDF

Matches the Go reference's key-file encryption format exactly — the TS
port additionally constrains the IV nibble to avoid a latent Go-side
edge case (≈6% failure rate in Go; 0% in TS).

### Historical curves (since `v1.1.0`)

Three extra curves from the author's original Cryptoplasm research phase,
named after the Delian family. Same structural family as DALOS (Twisted
Edwards, cofactor 4, negative `d`), smaller primes for research /
pedagogy / benchmarking. **Not production primitives** — the registry
never exposes them.

| Curve | Safe-scalar `S` | Prime `P` | Keyspace |
|---|---|---|---|
| `LETO` | 545 bits | `2^551 + 335` | 2⁵⁴⁵ ≈ 1.15 × 10¹⁶⁴ |
| `ARTEMIS` | 1023 bits | `2^1029 + 639` | 2¹⁰²³ ≈ 9.0 × 10³⁰⁷ |
| `APOLLO` | 1024 bits | `2^1029 + 639` | 2¹⁰²⁴ ≈ 1.8 × 10³⁰⁸ |

See [`docs/HISTORICAL_CURVES.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/HISTORICAL_CURVES.md)
for the full provenance, audit log, and usage.

### Deterministic RSA-4096 for Arweave (new)

The same custom seed phrase that mints your DALOS Genesis EC account can
*also* deterministically mint a real, standards-compliant **RSA-4096
keypair** — the exact key format Arweave requires. Same seed in, same
keypair out, byte-for-byte, forever, on any machine — including the
Arweave address.

**Why this doesn't normally exist:** RSA key generation is fundamentally
a probabilistic search for two large primes, not one algebraic step like
EC key derivation — and every mainstream RSA implementation deliberately
resists being made reproducible. We traced this ourselves rather than
assume it: Go's standard library silently ignores a caller-supplied
random source by default since Go 1.26, and even its escape hatch has a
coin-flip anti-determinism safeguard that's been there since 2018,
specifically to stop callers from relying on `rsa.GenerateKey` being
seed-reproducible. So this package doesn't wrap a standard RSA generator
— it implements the prime search itself from scratch (FIPS 186-5,
Miller-Rabin, unbiased rejection-sampled witnesses), sourcing every
single random-looking byte from one seeded Blake3-XOF stream. No
`crypto.getRandomValues`, no `Math.random`, no OS entropy anywhere in
the path — verified by grepping the entire dependency chain, not just
asserted.

Validated against **real, independent Arweave code**, not just internal
self-checks: the actual `arweave-core` package's `importKeyfile()` and
`addressOf()` accept the generated keys and reproduce the address
byte-for-byte, and Node's native WebCrypto completes a real RSA-PSS/
SHA-256 sign→verify round-trip with them. The Go reference and this TS
port are cross-validated field-by-field — including the exact internal
candidate-search counts, not just the final output — against a frozen
test-vector corpus.

As far as our research could establish, no other audited, production-
grade library exposes this. The one community project we found
attempting seed-derived Arweave keys uses non-standard derivation and
has open, reported determinism bugs — which lines up exactly with the
entropy-leak failure mode this package was built specifically to avoid.

```ts
import { generateFromBitString } from "@ouronet/dalos-crypto/rsa4096";

// Same 1600-bit seed you'd feed to DalosGenesis.generateFromBitString —
// deterministically produces a full RSA-4096 keypair + Arweave address
// instead of (or alongside) an EC account.
const bits1600 = "1".repeat(800) + "0".repeat(800);
const result = generateFromBitString(bits1600);

console.log(result.address);  // 43-char base64url Arweave address
console.log(result.jwk);      // canonical 9-field Arweave JWK (kty, n, e, d, p, q, dp, dq, qi)

// Same seed, run again (even on a different machine) -> identical output.
```

Generation costs low-single-digit seconds (finding two real 2048-bit
primes isn't cheap, and this runs **100** Miller-Rabin rounds per prime —
the top of the 64-100 range the design calls for, since this is a
one-time-per-seed operation with no per-transaction cost to amortize).
Use `generateFromBitStringAsync` for a UI: it yields to the event loop
periodically (same mechanism as `schnorrSignAsync`/`scalarMultiplierAsync`
above) so a real progress bar can actually repaint while it runs:

```ts
import { generateFromBitStringAsync, type ProgressEvent } from "@ouronet/dalos-crypto/rsa4096";

const bits1600 = "1".repeat(800) + "0".repeat(800);

function onProgress(ev: ProgressEvent) {
  // ev.stage is "p" or "q"; ev.overallProgress is a mathematically-honest
  // 0..1 estimate (a memoryless-search completion probability, not a
  // guess) suitable for driving a <progress> element directly.
  console.log(`${ev.stage}: attempt ${ev.attempts}, ~${(ev.overallProgress * 100).toFixed(0)}%`);
}

const result = await generateFromBitStringAsync(bits1600, onProgress);
console.log(result.address); // 43-char base64url Arweave address
```

The seed isn't hardcoded to DALOS Genesis's 1600 bits either — any
DALOS_Crypto curve's safe-scalar bitstring works unchanged (e.g. APOLLO's
1024 bits), since the construction has no structural opinion on seed
length; only a 128-bit sanity floor is enforced.

See [`.docs/deterministic-rsa4096-from-seed.md`](https://github.com/OuroborosNetwork/dalos-crypto/blob/main/.docs/deterministic-rsa4096-from-seed.md)
for the full design history, empirical research, and everything checked
along the way.

---

## Quick start

### Mint an Ouronet account (every mode)

```ts
import { type Bitmap } from "@ouronet/dalos-crypto/gen1";
import { DalosGenesis } from "@ouronet/dalos-crypto/registry";

// 1 — OS randomness (simplest)
const a = DalosGenesis.generateRandom();

// 2 — from a custom seed phrase (any language, 4–256 words)
const b = DalosGenesis.generateFromSeedWords([
  "mountain", "whisper", "aurora", "eternal", "signal", "zen",
]);

// 3 — from a 1600-bit binary string (any sequence qualifies)
const bits1600 = "1".repeat(800) + "0".repeat(800);
const c = DalosGenesis.generateFromBitString(bits1600);

// 4 — from a base-10 integer (must be in curve range; core throws if not)
const d = DalosGenesis.generateFromInteger("123456789012345", 10);

// 5 — from a base-49 integer (DALOS alphabet, 0-9 a-z A-M)
const e = DalosGenesis.generateFromInteger("hello42", 49);

// 6 — from a 40×40 bitmap (row-major, true = black, false = white)
//      Note: the TS port intentionally omits the Go reference's
//      ParsePngFileToBitmap helper (Bitmap/Bitmap.go:178). PNG decoding
//      adds bundle weight and assumes filesystem access not available
//      in browser environments. Construct the boolean[][] directly from
//      whatever input source you have (PNG via @napi-rs/canvas in Node,
//      <canvas> ImageData in browser, hand-painted via UI, etc.).
const bitmap: Bitmap = Array.from({ length: 40 }, () => Array<boolean>(40).fill(false));
const f = DalosGenesis.generateFromBitmap(bitmap);

// Every `FullKey` has:
console.log(f.keyPair.priv);          // base-49 private key
console.log(f.keyPair.publ);          // base-49 prefixed public key
console.log(f.privateKey.bitString);  // 1600-char binary
console.log(f.privateKey.int10);      // base-10 representation
console.log(f.privateKey.int49);      // base-49 representation
console.log(f.standardAddress);       // Ѻ.xxxxx…   (160 chars)
console.log(f.smartAddress);          // Σ.xxxxx…   (160 chars)

// All six paths feed the same Genesis pipeline; here are their addresses.
const accounts = [a, b, c, d, e, f];
console.log(`Generated ${accounts.length} accounts via 6 different input paths.`);
console.log(accounts.map((acc) => acc.standardAddress));
```

### Sign + verify (Schnorr v2)

```ts
import { SchnorrSignError, sign, verify } from "@ouronet/dalos-crypto/gen1";
import { DalosGenesis } from "@ouronet/dalos-crypto/registry";

const account = DalosGenesis.generateRandom();
let sig = "";
try {
  sig = sign(account.keyPair, "hello world");
} catch (e) {
  if (e instanceof SchnorrSignError) {
    console.error("sign failed:", e.message);
  }
  throw e;
}
console.log(verify(sig, "hello world", account.keyPair.publ)); // true
```

### Browser-friendly async signing (since v3.1.0)

For browser consumers running Schnorr at full curve scale, the
synchronous variants block the UI thread for hundreds of milliseconds
to seconds; the async variants yield to the event loop every 8
outer-loop iterations on a fixed data-independent cadence and keep
Interaction-to-Next-Paint (INP) under 200 ms.

Three additive functions, all re-exported from `@ouronet/dalos-crypto/gen1`:
`scalarMultiplierAsync`, `schnorrSignAsync`, `schnorrVerifyAsync`. The
yield trigger depends only on the scalar-mult outer-loop iteration
index — never on the scalar value or any secret-derived branch — so
the constant-time property of the synchronous path is preserved.
Output is byte-identical to the sync variants for the same inputs
(deterministic v2 RFC-6979-style nonces).

```ts
import { schnorrSignAsync, schnorrVerifyAsync } from "@ouronet/dalos-crypto/gen1";
import { DalosGenesis } from "@ouronet/dalos-crypto/registry";

const account = DalosGenesis.generateRandom();
const sig = await schnorrSignAsync(account.keyPair, "hello world");
console.log(await schnorrVerifyAsync(sig, "hello world", account.keyPair.publ)); // true
```

This is the recommended path for any UI thread that issues `Q-1`-scale
operations; the sync variants remain the default for Node/server
contexts where blocking is acceptable.

### AES encryption (Genesis-compatible key-file format)

```ts
import { decrypt, encrypt } from "@ouronet/dalos-crypto/gen1";

const cipher = await encrypt("secret message", "strong-password");
const recovered = await decrypt(cipher, "strong-password");
console.log(recovered === "secret message"); // true
```

### Detect which primitive minted an address

```ts
import { createDefaultRegistry, DalosGenesis } from "@ouronet/dalos-crypto/registry";

const registry = createDefaultRegistry();
const account = DalosGenesis.generateRandom();
const detected = registry.detect(account.standardAddress);
if (detected) console.log(detected.id); // "dalos-gen-1"
```

---

## Subpaths

```ts
// Per-subpath narrow imports (recommended for tree-shaking).
import { fromRandom } from "@ouronet/dalos-crypto/gen1";
import { createDefaultRegistry, DalosGenesis } from "@ouronet/dalos-crypto/registry";
import { LETO } from "@ouronet/dalos-crypto/historical";
import { blake3SumCustom } from "@ouronet/dalos-crypto/dalos-blake3";
import { generateFromBitString } from "@ouronet/dalos-crypto/rsa4096";

// All five subpaths exist; pick whichever surface area you need.
console.log(typeof fromRandom, typeof DalosGenesis, typeof createDefaultRegistry, typeof LETO, typeof blake3SumCustom, typeof generateFromBitString);
```

Every subpath has first-class TypeScript types.

---

## Byte-identity with Go reference

Core value proposition: **the same input produces the same output as the
Go service at `go.ouronetwork.io/api/generate`**. The port is validated
against 105 canonical test vectors:

- 50 bitstring → keys → addresses
- 15 seed-word fixtures (ASCII + Unicode)
- 20 bitmap fixtures (hand-designed + deterministic-random)
- 20 Schnorr sign + self-verify

Plus `[Q]·G = O` end-to-end verification per curve. The RSA-4096 package
carries the same guarantee against its own frozen corpus
(`testvectors/v2_rsa4096.json`) — every field of every vector, including
the exact internal candidate-search counts (proof the two
implementations consume the seed identically, not just coincidentally
agree on the final key). Run locally:

```bash
npm test   # 431 tests, ~30s
```

See the Go-reference corpora: [`testvectors/v1_genesis.json`](https://github.com/StoaChain/DALOS_Crypto/blob/main/testvectors/v1_genesis.json)
and [`testvectors/v2_rsa4096.json`](https://github.com/StoaChain/DALOS_Crypto/blob/main/testvectors/v2_rsa4096.json).

---

## Security notes

- **No console leakage.** The library never logs key material.
- **Constant-time where it matters.** The base-49 Horner scalar-mult
  uses a branch-free linear scan over the precompute matrix (SC-7).
  See `src/gen1/scalar-mult.ts` + [`docs/SCHNORR_V2_SPEC.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/SCHNORR_V2_SPEC.md).
- **Genesis freeze.** Key-generation output is permanently frozen at
  v1.0.0. Any future additions (new input modes, new curves) MUST
  preserve byte-identity for existing inputs. The historical curves
  added in v1.1.0 are additive and do not alter Genesis behaviour.
- **Schnorr v2 deterministic nonces** — signatures are reproducible
  from `(message, privateKey)`; there is no randomness dependency and
  no nonce-reuse attack surface.
- **AES-256-GCM IV constraint** — TS port rejects IVs whose high
  nibble is zero, eliminating a latent round-trip failure present in
  the Go reference (~6% of randomly-generated IVs). Ciphertexts
  produced by the TS port decrypt cleanly on both TS and Go sides.
- **RSA-4096 touches zero real entropy, verified not just asserted.**
  The entire dependency chain — `src/rsa4096/*`, the Blake3-XOF stream
  it's built on, and `@noble/hashes`'s underlying `blake3`/`sha2`
  implementations — was grepped for `Math.random`, `crypto.getRandomValues`,
  and every other entropy source; there are none. Every byte the prime
  search consumes traces back deterministically to the input seed.

---

## Licence

Proprietary — Copyright © 2026 AncientHoldings GmbH. All rights reserved.
See [`../LICENSE`](https://github.com/StoaChain/DALOS_Crypto/blob/main/LICENSE).

---

## Links

- Main repo: [github.com/StoaChain/DALOS_Crypto](https://github.com/StoaChain/DALOS_Crypto)
- Architecture deep-dive: [`docs/DALOS_CRYPTO_GEN1.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/DALOS_CRYPTO_GEN1.md)
- TS port phase tracker: [`docs/TS_PORT_PLAN.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/TS_PORT_PLAN.md)
- Historical curves: [`docs/HISTORICAL_CURVES.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/HISTORICAL_CURVES.md)
- Schnorr spec: [`docs/SCHNORR_V2_SPEC.md`](https://github.com/StoaChain/DALOS_Crypto/blob/main/docs/SCHNORR_V2_SPEC.md)
- Gitbook: [demiourgos-holdings-tm.gitbook.io](https://demiourgos-holdings-tm.gitbook.io/kadena/ouro-network-cryptography)
