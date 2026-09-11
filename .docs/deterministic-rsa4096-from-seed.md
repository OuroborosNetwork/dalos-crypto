# Deterministic RSA-4096 Key Generation from an Arbitrary Seed

**Status:** **shipped, both languages.** All 11 implementation steps complete (2026-09-11) — Go reference at `RSA4096/` and TypeScript port at `ts/src/rsa4096/` (`@ouronet/dalos-crypto/rsa4096`), both graduated from the `research/rsa4096-poc/` prototype into the real package, with a frozen, CI-pinned test-vector corpus (`testvectors/v2_rsa4096.json`) and full cross-language byte-identity (`ts/tests/rsa4096/rsa4096.test.ts` — every field, including exact candidate-attempt counts). See §9 "Implementation Log" (steps 1-9, prototype + research) and §10 "Implementation Log" (steps 10-11, graduation + TS port) at the end of this document. Validated against **real, independent code** throughout — `arweave-core`'s actual `importKeyfile`/`addressOf`, and Node's native WebCrypto RSA-PSS sign/verify — not just internal self-checks. Remaining before production use: wiring into Codex's actual key-generation flow (Codex-side work), and the live-gateway transaction test (deliberately not attempted autonomously at any point — needs a funded wallet and a human present; this is the user's own explicit next step).

**Goal:** given a fixed input seed (e.g. a 1600-bit bit-string derived from DALOS's custom seed-word mechanism), deterministically produce a real, standards-compliant, fully usable RSA-4096 keypair (the format Arweave wallets require) — such that the same seed always regenerates the exact same keypair, byte-for-byte, forever, on any machine.

**Why this matters:** DALOS already has a working, audited path from arbitrary seed words to a deterministic elliptic-curve private key. Arweave's protocol requires RSA-4096/JWK keys specifically — a completely different algebraic structure that cannot be produced from an EC key by conversion. This is a project to give DALOS's seed-word mechanism an equivalent deterministic path to a *real, network-valid* Arweave RSA-4096 key. As far as this research could establish, no mainstream, audited implementation of this exists today — the one community attempt found (`arweave-mnemonic-keys`) is non-standard HD derivation and has had reported determinism bugs.

---

## 1. The one-sentence mental model

An RSA-4096 key isn't one random number — it's **two independent large primes**, `p` and `q` (each ~2048 bits), found by *searching*: generate a candidate, test if it's prime, repeat until you get lucky. Normal ("real") key generation draws that search's randomness from the OS's true entropy pool. **Deterministic** generation draws the exact same *kind* of randomness — a cryptographically strong pseudorandom stream — from a fixed, seeded source instead. The algorithm doesn't change; only where its randomness comes from changes. Every OS's "random" numbers already work this way structurally (true entropy seeds a deterministic expansion algorithm) — the only difference here is that *we* choose and fix the seed instead of letting the OS pick a fresh unrecoverable one.

## 2. Why this is genuinely harder than DALOS's existing EC seed-derivation

EC key derivation from a seed is one hash + one scalar multiplication — fast, and trivially, robustly deterministic by construction; there's no search, no loop, nothing that can go non-deterministic partway through. RSA key generation requires an **iterative prime search**: draw a candidate, test it, maybe reject and retry, possibly hundreds of times per prime. Every one of those draws — including the randomness *primality testing itself* needs internally — has to come from the seeded stream. Miss even one call site anywhere in the dependency chain that quietly falls back to real system entropy, and the result is silently non-deterministic — this is almost certainly the exact failure mode behind the known `arweave-mnemonic-keys` bug reports (same "seed" producing a different address on different runs).

**The correctness bar is not "test it many times and see if it repeats."** Repeated testing is a statistical hint, not proof — it can get lucky. The actual guarantee has to be structural: audit every random-consuming call site in the entire dependency chain (including third-party library internals) and prove none of them ever touch anything but the seeded stream.

## 3. Why most existing crypto libraries fight you on this (this is deliberate, not an oversight)

Standard APIs (WebCrypto's `crypto.subtle.generateKey()`, most language stdlibs) deliberately expose **no way to inject a custom seed** into RSA generation. This isn't negligence — for the overwhelming majority of callers, an easily-misusable "give me a seed" parameter is a foot-gun: an accidental weak/hardcoded seed, or worse, a *deliberately* backdoored implementation that looks secure while being predictable. This exact shape of vulnerability is not hypothetical — the NIST-approved `Dual_EC_DRBG` random-number-generator standard is widely accepted to have had precisely this kind of hidden weakness (strongly suspected NSA backdoor). Library authors reasonably decided the safety of the common case outweighs convenience for the rare deterministic-generation use case, and expect anyone who genuinely needs it to build and fully own that tooling themselves.

This is also why elliptic curves got a mature, standardized deterministic-derivation scheme (BIP32, widely used for HD wallets) while RSA never did: EC derivation is cheap and trivially safe to standardize; RSA's iterative search is inherently harder to make airtight, so the ecosystem concentrated effort where the safety/effort ratio was favorable.

## 4. Verified cryptographic facts this design relies on (established during this research pass)

- **1 AR = 1,000,000,000,000 Winston** (10¹², confirmed from `@ancientpantheon/arweave-core`'s source).
- **Arweave address = Base64URL(SHA-256(RSA public modulus `n`))**, 43 characters for a 4096-bit key (confirmed by decoding a real address: 43 base64url chars → exactly 32 bytes → 256 bits, matching a SHA-256 output exactly).
- **RSA-4096's real cryptographic strength is ~156 bits** (computed directly from the General Number Field Sieve's published complexity formula, not just asserted — GNFS is *sub-exponential* in key size, unlike EC's Pollard's-rho attack which is genuinely exponential/`O(√N)`). This is *why* RSA needs thousands of raw key bits to achieve what EC achieves in a few hundred — the two systems' attack complexity scales completely differently with key size, so raw bit-length isn't comparable across them.
- **A 2048-bit number spans `2^2047` to `2^2048 − 1`** — a ~617-digit decimal range. The count of primes in that range is approximately **`2^2037`** (Prime Number Theorem: `π(2^2048) ≈ 2^2048 / ln(2^2048)`) — vastly larger than the number of atoms in the observable universe (`~2^266`). Collision risk between independently-generated primes is not a practical concern at any conceivable scale (computed: even `2^100` keys ever generated — far beyond anything real — gives a collision probability of roughly `2^-1839`).
- **Primality testing in practice is probabilistic (Miller-Rabin), not a mathematical proof of primality** — this is standard, accepted practice; the residual false-positive probability is engineered (via round count) to sit far below every other real-world failure mode in the system (hardware bit-flips, hash collisions), not eliminated entirely. A false positive would matter if it happened — the resulting "prime" would actually be a product of two smaller primes, making the modulus significantly easier to factor — which is exactly why this design should over-provision Miller-Rabin rounds rather than use the bare minimum.

## 5. The design, step by step

### 5.0 — Resolve this FIRST, before writing any other code

Go's standard library `crypto/rsa.GenerateKey(random io.Reader, bits int)` **already accepts a caller-supplied entropy source** — this is a first-class, documented part of the API, not a hack. If Go's internal implementation genuinely and unconditionally threads that supplied reader through the *entire* prime-search process with zero additional entropy mixed in from anywhere else, **this could mean reusing Go's own battle-tested standard-library RSA generator directly** — supplying a deterministic `io.Reader` (backed by the DRBG from §5.1) — instead of writing bignum/primality-testing code from scratch. That would be a massive reduction in custom cryptographic surface area.

**However**, tracing the actual source found a real wrinkle: `GenerateMultiPrimeKey` wraps the caller's reader through `rand.CustomReader(random)`, and there's a `GODEBUG=cryptocustomrand=1` flag gating custom-reader behavior in recent Go versions — this has the shape of a FIPS-140-compliance guard, where certified crypto modes may restrict or transform custom entropy sources. **This was not resolved in this research pass and must be the first task**: read `crypto/rand.CustomReader`'s actual implementation directly and confirm definitively whether it's a clean pass-through of the supplied bytes, or whether it mixes in anything else.

- **If it's a clean pass-through**: write a minimal proof-of-concept — same seed, called twice, confirm byte-identical `p`/`q`/`n`/`d` output. If confirmed, skip most of §5.2 and go straight to §5.3.
- **If it's not a clean pass-through** (or behaves differently across Go versions/build flags): proceed with building the prime-search loop directly, as described in §5.2.

### 5.1 — Seed → deterministic expandable stream

A single hash call isn't enough raw material — finding a 2048-bit prime needs on the order of hundreds of kilobits of pseudorandom material (many ~2048-bit candidate draws before hitting a prime), far more than one hash's fixed output size. Use a proper **extendable-output function or DRBG**:

- **HMAC_DRBG** (NIST SP 800-90A) — recommended primary choice. This is literally the standards body's purpose-built answer to "deterministic random bit generator," with a published security proof and wide real-world deployment. Go's stdlib doesn't ship it directly; evaluate audited third-party Go implementations.
- **SHAKE256** (FIPS 202 / SHA-3 family) — simpler fallback. A true extendable-output function: absorb the seed, squeeze out as much deterministic output as needed. Available via `golang.org/x/crypto/sha3`.

Whichever is chosen: seed it **once**, then draw everything needed for both `p` and `q` (and all of Miller-Rabin's internal witness randomness) from that single continuous stream — never re-seed mid-generation.

### 5.2 — Deterministic candidate generation + primality testing (only if §5.0 requires building this from scratch)

Follow **FIPS 186-5** (NIST's actual standard for *how* to correctly generate RSA keys) for the procedure itself, swapping only its randomness source:

1. Draw 2048 bits from the seeded stream.
2. Standard bit-fixing: force the top two bits to `1` (guarantees the final modulus is exactly the intended bit-length), force the bottom bit to `1` (odd).
3. Cheap trial-division against small primes (fast rejection of most composites, pure speed optimization).
4. Primality test survivors with a **high, fixed Miller-Rabin round count** (64–100 rounds — deliberate over-provisioning; the extra compute cost is trivial against a multi-minute generation budget, and removes reliance on subtler statistical arguments about non-adversarial input). Consider adding a **Lucas test** for a combined **Baillie-PSW** test, matching what OpenSSL/GMP actually do in production — no composite number is currently known to pass full Baillie-PSW.
5. If composite, draw the next 2048 bits from the *same* stream and retry.
6. On success, that's `p`. **Do not reset the stream** — continue drawing from it to find `q` the same way.
7. Enforce FIPS 186-5's auxiliary robustness checks: `p ≠ q` (explicit defensive check even though collision is astronomically unlikely), minimum distance `|p − q|` large enough to resist Fermat factorization, `gcd(e, p−1) = 1` and `gcd(e, q−1) = 1` for `e = 65537` (retry on the rare failure).

### 5.3 — Key assembly + interop validation (required regardless of which path §5.0 lands on)

- `n = p × q`, `e = 65537` (standard, fixed), `d = e⁻¹ mod λ(n)` — **confirm which convention** (`φ(n)` vs. Carmichael's `λ(n)`) matches what `arweave-js`/`@ancientpantheon/arweave-core` actually expect, so the resulting JWK is interoperable with the real network, not just internally self-consistent.
- Compute the CRT parameters the JWK format requires: `dp = d mod (p−1)`, `dq = d mod (q−1)`, `qi = q⁻¹ mod p`.
- **The real test is not "our code thinks this is valid."** Feed the generated JWK into `arweave-core`'s own `addressOf()` and confirm a well-formed 43-character address; then actually sign and submit a real transaction with it and confirm a live gateway accepts it. That's the only test that proves real-network interoperability.
- Build a **golden test-vector file**: a fixed set of seeds with their locked-in expected `p`/`q`/`n`/`d` output, generated once. Every future change to the implementation — including the eventual JS port — must reproduce these exactly, not just "run without error."

## 6. Language / porting strategy

**Go is the right language to prototype and harden this in** — `math/big` is mature, heavily battle-tested (it underlies Go's own `crypto/rsa`), DALOS_Crypto already uses Go for the existing elliptic-curve work (`Dalos.go`), and it's a comfortable environment for rigorous property-based testing.

**But this must eventually run in a browser, inside Codex** — so whatever gets proven correct in Go still needs a faithful port to JS/WASM for production use, and that port is itself a real, separate risk: two independent implementations of the same algorithm producing byte-identical output for the same seed is not automatic. Plan this as an explicit deliverable: reuse the exact golden test vectors from §5.3 to validate the JS port against the Go reference implementation, not just against itself.

## 7. Summary of open research tasks, in priority order

1. **(Highest priority)** Resolve §5.0 — does Go's `crypto/rsa.GenerateKey` + `rand.CustomReader` give a clean, unconditional pass-through of caller-supplied randomness, or does it mix in anything else / behave differently under `GODEBUG=cryptocustomrand`? This single answer determines whether most of §5.2 is even necessary.
2. Evaluate audited Go implementations of HMAC_DRBG (SP 800-90A) vs. defaulting to SHAKE256 for simplicity.
3. If building the prime search from scratch: implement per FIPS 186-5, over-provisioned Miller-Rabin (64–100 rounds) + optional Baillie-PSW, sourced entirely from the seeded stream with zero unaudited third-party calls.
4. Confirm the `φ(n)` vs. `λ(n)` convention `arweave-core`/`arweave-js` actually expect.
5. Build the golden test-vector suite and the real-network interop test (sign + submit against a live gateway).
6. Scope and execute the JS/WASM port, validated against the same golden vectors.

---

## 8. Decision Record — 2026-09-11: §5.0 resolved

**Method:** installed Go locally (none was present) and traced the actual stdlib source under `$GOROOT/src/crypto/{rand,rsa}` and `$GOROOT/src/math/big/prime.go` directly, rather than reasoning from docs/memory. Toolchain: apt's `golang-go` supplied Go 1.26.0; manually upgraded to **1.27.1** (latest stable as of this date — tarball SHA-256 verified against the official `go.dev/dl/?mode=json` manifest before install) via a side-by-side install at `/usr/local/go1.27.1` with `/usr/bin/go` repointed at it. Confirmed `go build ./...` and `go vet ./...` on this repo's root module are clean under 1.27.1 before proceeding — no toolchain regression.

### 8.1 Finding: `crypto/rsa.GenerateKey` cannot be used, and this is permanent by design

Two independent, stacked reasons, both confirmed by reading source (not changelogs):

1. **`crypto/internal/rand.CustomReader`** (`rand.go`): as of **Go 1.26** (`internal/godebugs/table.go`: `{Name: "cryptocustomrand", Changed: 26, Old: "1"}`), any caller-supplied `io.Reader` passed to `rsa.GenerateKey`/`GenerateMultiPrimeKey` is **silently discarded and replaced** with Go's internal FIPS-140 DRBG reader, unless the process sets `GODEBUG=cryptocustomrand=1`. The doc comment on `GenerateMultiPrimeKey` states outright that this GODEBUG escape hatch itself **"will be removed in a future Go release."** So even the workaround has a scheduled expiry.
2. **`crypto/internal/randutil.MaybeReadByte`** (present since 2018, independent of finding #1): even with the GODEBUG flag set, `CustomReader` calls this first — it consumes a byte from the supplied reader with a `math/rand/v2`-driven 50% coin flip, specifically so that "callers do not depend on non-guaranteed behaviour, e.g. assuming that rsa.GenerateKey is deterministic w.r.t. a given random stream" (verbatim doc comment — it names our exact use case as the thing it exists to prevent). Go's own test suite works around this with a reader hack annotated **"DO NOT COPY this. We will break you... You have been warned."**

**Verdict:** this is not a version quirk to wait out or a flag to set — it is deliberate, permanent Go policy against exactly what we're trying to do. §5.2 (build the FIPS 186-5 prime search ourselves) is **mandatory**, not a fallback path.

### 8.2 Finding: `math/big.Int.ProbablyPrime` itself is safe, but shouldn't be our primality gate

Traced separately since it's the actual primality test, decoupled from `rsa.GenerateKey`. It reseeds a fresh `math/rand` v1 source from the candidate's own low word (`rand.New(rand.NewSource(int64(n[0])))`) — no OS entropy, no global state, no dependency on `crypto/rand` at all. `math/rand` v1's output stream is explicitly frozen forever under the Go 1 compatibility promise (confirmed in `math/rand/rand.go` comments: *"Go 1 compatibility requires that the stream of values produced by math/rand remain unchanged"*). So `ProbablyPrime` is genuinely, permanently deterministic per input.

**Decision: don't rely on it directly anyway.** Two reasons: (a) it ties a random consumer to Go-internal plumbing instead of our own audited seeded stream — the doc's own §2 correctness bar demands *every* random draw be provably tied to the seed, and this one technically isn't, even though it happens to be safe; (b) it's Go-specific machinery (a particular PRNG algorithm + witness-selection scheme) that doesn't port to TypeScript without reimplementing Go's internal `math/rand` algorithm there too. Instead: hand-roll a plain Miller-Rabin loop per FIPS 186-5, with witnesses drawn from *our* seeded DRBG stream (high fixed round count, 64–100 per §5.2), using `math/big` only for bignum arithmetic primitives (`Exp`, `ModInverse`, etc.) — not its `ProbablyPrime` convenience wrapper. Symmetric, portable, and keeps the audit story airtight in both languages. (Caveat logged for later: `math/big`'s witness generation consumes a different number of PRNG words on 32-bit vs 64-bit builds — moot for us since we hand-roll this anyway, but worth remembering if `ProbablyPrime` is ever used as a secondary sanity check.)

### 8.3 Decision: use Blake3-XOF as the §5.1 seed-expansion stream, not HMAC_DRBG/SHAKE256

Both language sides of this repo already have an audited, cross-validated Blake3 **XOF** (extendable-output function), which is exactly the primitive §5.1 asked for:

- Go: `Blake3/Blake3.go` — `Hasher.XOF()` returns an `OutputReader` (`io.Reader`) documented as "a seekable stream of 2^64 − 1 pseudorandom output bytes."
- TS: `ts/src/dalos-blake3/index.ts` — wraps `@noble/hashes/blake3` with `dkLen`, asserted byte-identical to the Go side for every input/output-length combination.

Reusing this avoids introducing a brand-new primitive/dependency, and it slots into the existing domain-tag convention (`DALOS-gen1/SchnorrHash/v1`, `DALOS-gen1/SchnorrNonce/v1`) with a new tag, e.g. `DALOS-gen1/RSA4096Stream/v1`. Supersedes §5.1's HMAC_DRBG/SHAKE256 suggestion unless a future audit specifically wants a NIST-standardized DRBG for optics.

### 8.4 Decision: prototype in an isolated nested Go module, not the root module

The root module's CI (`go-ci.yml`) runs `go build ./...`, `go vet ./...`, and the corpus byte-identity gate on every push touching Go code. This work is pre-implementation research, per this doc's own status line — dropping in-progress code into the root module tree would make half-finished prototypes look like production packages and risk tripping gates on unrelated pushes. Plan: scaffold `research/rsa4096-poc/` as its **own nested Go module** (own `go.mod`, `go 1.27`), which Go's tooling treats as invisible to the parent module's `./...` — full freedom to iterate. Once the DRBG + Miller-Rabin design is proven (self-consistent, cross-checked, ideally validated against real Arweave interop per §5.3), graduate the working code into a real top-level package (e.g. `RSA4096/`, sibling to `Elliptic/`) following `docs/ADDING_NEW_PRIMITIVES.md`'s playbook exactly — new corpus file, new generator function, CI baseline pin, TS port before merge.

---

## 9. Implementation Log — 2026-09-11: steps 1-9 built and validated (`research/rsa4096-poc/`)

Working autonomously overnight per direct instruction, on top of §8's decisions. Toolchain: Go 1.27.1 (installed this session, see §8). Everything below lives in `research/rsa4096-poc/` (its own nested module, per §8.4) and is **prototype-stage**: dummy, non-DALOS seeds throughout, nothing frozen yet.

### 9.1 What was built

- **`stream.go`** (step 1): `NewSeedStream(seedBitString string) (io.Reader, error)` — Blake3-XOF tap per §8.3, domain tag `DALOS-gen1/RSA4096Stream/v1`, length-prefixed framing matching `Schnorr.go`'s convention. Seed is hashed as its literal ASCII bytes (not bit-packed) — deliberate, to avoid an MSB/LSB ordering footgun between the eventual Go and TS implementations.
- **`candidate.go`** (step 2): `GenerateCandidate` — pulls 256 fresh bytes, forces top two bits + bottom bit to `1`. Every candidate is provably exactly 2048 bits, odd, by construction.
- **`primes.go`** (step 3): trial division against the first 2000 odd primes, generated via a plain Sieve of Eratosthenes at call time (not a hardcoded literal table — see the chat log for the reasoning: cross-language safety and auditability both favor computing it over transcribing it twice).
- **`millerrabin.go`** (step 4): hand-rolled Miller-Rabin, 64 rounds, witnesses drawn from the seed stream via **rejection sampling** (not `mod`) — see §9.3, this was a real bug caught and fixed during review tonight.
- **`primesearch.go`** (step 5): `FindPrime` (single-prime search + the `gcd(e, prime-1) == 1` check, which is a single-prime property) and `FindTwoPrimes` (the genuinely pairwise checks: `p != q`, `|p-q| > 2^1948` per FIPS 186-5's Fermat-factorization-resistance bound). Only the failing prime gets redrawn on a per-prime check failure; only a fresh `q` gets redrawn (keeping `p`) on the astronomically-rare pairwise failure.
- **`keyassembly.go`** (step 6-7): `n = p*q`, `e = 65537`, `d = e⁻¹ mod λ(n)` (Carmichael, not Euler — see §9.2), `dp`, `dq`, `qi`.
- **`jwk.go`** + **`pipeline.go`** (local half of step 8): canonical 9-field Arweave JWK encoding, `AddressOf` (`Base64URL(SHA-256(n))`), and `SelfCheckTextbookRSA` (raw encrypt/decrypt + sign/verify round-trip, independent of any padding scheme).
- **`validate.mjs`** / **`validate_golden.mjs`** (external half of step 8): cross-checks against the **real, compiled `arweave-core` package** (`AncientPantheon/constructors/Codex/packages/arweave-core/dist`) and **Node's native WebCrypto** (RSA-PSS/SHA-256 import + sign + verify) — not our own code.
- **`main.go`** (step 9): runs the full pipeline, writes `jwk.json` and `golden_vectors.json` (5 fixed dummy seeds).

### 9.2 Research finding: resolved the φ(n)/λ(n) convention question empirically, not by assumption

Found the real `arweave-core` package locally (`AncientPantheon/constructors/Codex/packages/arweave-core`) and read its actual source:

- `src/keys/generate.ts`: the real seedless key-gen path calls `globalThis.crypto.subtle.generateKey({name: "RSA-PSS", modulusLength: 4096, publicExponent: [1,0,1], hash: "SHA-256"}, ...)` — i.e., convention is whatever the **platform WebCrypto/OpenSSL** does, not anything Arweave-specific.
- `src/keys/keyfile.ts`'s `importKeyfile`: validates `kty`, base64url alphabet, `n`'s decoded length (512 bytes), and `e === "AQAB"` — **never** cross-checks `d`/`p`/`q`/`dp`/`dq`/`qi` for mathematical consistency. Confirms neither convention could ever be "rejected" on import.
- `src/keys/address.ts`'s `addressOf`: `Base64URL(SHA-256(decode(n)))`, depends on `n` alone.

Then generated a real key with `openssl genrsa 4096` and checked empirically (Python, `pow(e, -1, lam) == d`): **OpenSSL uses λ(n)**, not φ(n) (`e*d mod φ(n) == 1` is `False`; `e*d mod λ(n) == 1` is `True`). Decision: use λ(n), matching real-world practice, though the doc's original concern (§5.3's "confirm which convention") turned out to be lower-stakes than framed — both conventions are provably correct (proof: since `λ(n) | φ(n)`, any `d` valid mod `φ(n)` is automatically also valid mod `λ(n)`), and neither the address nor `arweave-core`'s import path can ever be affected by the choice. The only real stake is Go/TS agreement.

### 9.3 Bug caught in review: Miller-Rabin witness modulo bias

An adversarial multi-lens review (`code-review` skill, run autonomously) surfaced a real, non-cosmetic issue: `generateWitness` originally reduced the witness via `raw mod (n-3)`. Since every candidate has its top two bits forced to `1` (bit-fixing), `n` always sits in `[0.75 × 2^2048, 2^2048)`, and `n-3` does not evenly divide `2^2048` — so the naive `mod` reduction was **measurably biased** toward the low end of the valid witness range, for every single witness this codebase would ever draw (not a rare edge case).

Fixed via rejection sampling: draw 256 bytes, accept only if `raw < n-3` (discard and redraw otherwise). Since this simplifies to comparison + conditional add (no `mod` at all), it's also simpler to port to TypeScript than the original formula. Verified via a controlled, single-process A/B test (both schemes run back-to-back against the identical seed) that the fix produces byte-identical `p`/`q` to the pre-fix version for this seed — and traced *why*: non-surviving candidates (the ~90% majority) always consume exactly one stream chunk regardless of scheme (trial division never touches witnesses), so the two schemes only ever differ in how many extra chunks a *surviving* candidate's witness testing consumes. That difference never skips or duplicates a chunk — it just relabels the "attempt number" of everything downstream by a constant offset until the next survivor. Since compositeness (round-0 catches virtually all composites regardless of witness) and primality (true primes pass unconditionally) are both scheme-independent verdicts, both schemes are *guaranteed* — not merely likely — to converge on the same final prime. Confirmed this is not a fluke: all 5 golden-vector seeds showed the identical pattern (differing attempt counts, byte-identical final addresses).

Other review findings applied: moved `gcd(e, prime-1) == 1` from the pairwise check into `FindPrime` itself (a single-prime property was incorrectly invalidating an already-valid partner prime on failure); fixed an `RSAKey.E` field aliasing the shared `publicExponent` singleton pointer (dormant today, a real latent risk given this repo's established "zero sensitive `big.Int`s after use" convention); precomputed the small-prime trial-division divisors and `n-3` once instead of reallocating per-call; removed a `p == q` check subsumed by the `|p-q|` distance check; fixed error-discarding and a seed-independent test assumption in `main.go`'s self-checks; removed a stray unstripped compiled binary + added `.gitignore`. Full findings available in the session transcript if needed later.

### 9.4 Validation results

`go run .` (dummy seed + 5 golden-vector seeds), then `node validate.mjs` / `node validate_golden.mjs`:

- All internal self-checks pass: exact 2048-bit/odd/top-two-bits-set candidates, full-pipeline determinism (same seed twice → identical `n` and `d`), textbook RSA round-trip (encrypt/decrypt AND sign/verify) for 4 test messages, `n` always exactly 4096 bits, address always exactly 43 base64url characters.
- **`arweave-core`'s real, compiled `importKeyfile()` accepts every generated JWK.**
- **`arweave-core`'s real `addressOf()` computes the exact same address as our Go `AddressOf()`**, byte-for-byte, for all 6 keys generated this session.
- **Node's native WebCrypto imports the JWK as a real RSA-PSS/SHA-256 key pair and a real sign→verify round-trip succeeds**, for all 6 keys.
- Timing: ~0.7-5s per full RSA-4096 key generation (varies with system load), consistent with `arweave-core`'s own doc comment estimate ("~1s measured on Node v24") for ordinary (non-deterministic) RSA-4096 generation — i.e., this from-scratch deterministic implementation is not meaningfully slower than the platform's own generator.

### 9.5 Deliberately NOT done tonight

The live-gateway half of step 8 — signing and submitting a real transaction to a live Arweave gateway — was **not attempted**, on purpose. That requires a funded wallet and is an irreversible, real-value action; it needs a human present, not an autonomous overnight call. Steps 10 (graduate into a real `RSA4096/` package with a frozen corpus + CI pin, per `docs/ADDING_NEW_PRIMITIVES.md`) and 11 (TypeScript port, validated against the same golden vectors) are queued for the next session, as agreed.

---

## 10. Implementation Log — 2026-09-11 (later the same day): steps 10-11, graduation + TS port

Picked back up per direct instruction: "embed this into the package, with steps 10 and 11, so I can then add it as a generation key mechanic in Codex." Codex (`AncientPantheon/constructors/Codex`) is confirmed to be a TypeScript monorepo — its `codex-ouronet` package already imports `@ouronet/dalos-crypto/registry` and `/gen1` for its existing seed-derivation flow — so the TypeScript port (§10.3) is the piece that actually matters for the stated integration goal, not just a parity exercise.

### 10.1 Go graduation (step 10)

- New top-level package `RSA4096/` (sibling to `Elliptic/`, `AES/`, `Blake3/`), inside the real `DALOS_Crypto` module — moved verbatim from `research/rsa4096-poc/`, package renamed, two constants exported (`MillerRabinRounds`, `SmallPrimeCount` — were private in the prototype; exported so the corpus generator and any future introspection can reference them instead of hardcoding a second copy of the same numbers), `GenerateFullKey` renamed to `GenerateFromBitString` to match this codebase's `GenerateFrom*` naming convention (`Apollo.generateFromBitString`, `Ellipse.GenerateScalarFromBitString`).
- Real Go tests added (`RSA4096/rsa4096_test.go`, 11 tests, 3.5s): bit-fixing invariants, stream determinism, sieve correctness, and — notably — a cross-check of the hand-rolled Miller-Rabin against `math/big.Int.ProbablyPrime` as an **independent oracle**. (We deliberately don't use stdlib `ProbablyPrime` in *production* — see §8.2 — but it's an excellent independent check in *tests specifically*: if our from-scratch implementation ever disagreed with a completely differently-implemented primality test, that's a real bug worth catching immediately.)
- `go build ./...`, `go vet ./...`, `go test ./...` all clean for the whole root module. One **pre-existing, unrelated** test failure found in `DALOS_Crypto/keystore` (`TestExportPrivateKey_FileCreateFailure_ReturnsError` expects a stale error-message string the current `export.go` no longer produces) — confirmed to fail identically in isolation, confirmed this session never touched `keystore/`; flagged, not fixed (out of scope).
- `testvectors/generator/main.go`: new `generateRSA4096()` function, dedicated RNG seed `RNG_SEED_RSA4096 = 0xC0DE4096` (never shared with the EC-path seeds), writes the new `testvectors/v2_rsa4096.json` (3 vectors: 2 RNG-driven 1600-bit bitstrings + 1 real DALOS seed-word fixture reused from the existing `seedWordFixtures[0]`, tying the RSA output to the *same* seed a user would already use for their EC address). Kept to 3 vectors deliberately — each full RSA-4096 generation costs low-single-digit seconds, and this generator re-runs on every CI push touching Go code.
- **Byte-identity of the existing corpora verified before AND after the change**: `v1_genesis.json` and `v1_historical.json` both reproduce their documented frozen SHA-256 exactly (`082f7a40...`, `80c93f4d...`) — confirmed against the true git-committed (LF) baseline, not the working tree (which has an unrelated, pre-existing CRLF line-ending corruption affecting the *entire* repo — confirmed via `git diff --ignore-all-space` showing zero content difference on every affected file; not this session's doing, flagged separately).
- **Found, independently, a pre-existing CI-breaking issue**: `v1_adversarial.json`'s actual committed content does not match the SHA-256 pinned in `.github/workflows/go-ci.yml`'s `BASELINES` array (committed: `582025b1...`; pinned: `b9f228943106...`). This session's change did not touch or cause this — confirmed by regenerating and observing the *same* `582025b1...` hash both before and after adding `generateRSA4096()`. Not fixed here (per the playbook's explicit rule: never edit an existing BASELINES entry to silence a gate; the drift's root cause needs its own investigation). Flagged for the project maintainer.
- `v2_rsa4096.json`'s elided SHA-256 confirmed stable across 3 independent regenerations (`b0573a4dc48b55f2394e68fe2a17108e7a3a4bd1dbb781d8c3230984a5470499`) before pinning it into `go-ci.yml`'s `BASELINES`.

### 10.2 `research/rsa4096-poc/` demoted to a thin external-validation harness

Once `RSA4096/` existed as a real, importable package, the prototype's own copies of `stream.go`/`candidate.go`/`primes.go`/`millerrabin.go`/`primesearch.go`/`keyassembly.go`/`jwk.go`/`pipeline.go` became exact duplicates — a real drift risk (two copies of the same algorithm in one repo) with zero remaining benefit. Deleted them; `research/rsa4096-poc/main.go` now just imports `DALOS_Crypto/RSA4096` by local path, reads the real frozen `testvectors/v2_rsa4096.json`, regenerates each vector through the real package, and writes `jwk.json` / `golden_vectors.json` for `validate.mjs` / `validate_golden.mjs` to check against real `arweave-core` + Node WebCrypto — same role as before (§9.4), now validating the *actual shipped* corpus instead of throwaway dummy seeds. Re-ran both scripts against the real package: all 3 real vectors pass real `arweave-core` `importKeyfile()`/`addressOf()` (address matches byte-for-byte) and a real WebCrypto RSA-PSS sign→verify round-trip.

### 10.3 TypeScript port (step 11)

New `ts/src/rsa4096/` (`bigint-math.ts`, `stream.ts`, `candidate.ts`, `primes.ts`, `millerrabin.ts`, `primesearch.ts`, `keyassembly.ts`, `jwk.ts`, `pipeline.ts`, `index.ts`), file-for-file mirroring `RSA4096/*.go`. Notable porting decisions:

- **No new dependency.** Native `BigInt` has no built-in modular exponentiation, gcd, or modular inverse (Go's `math/big.Int` provides `Exp`/`GCD`/`ModInverse` directly) — hand-rolled square-and-multiply modexp and the extended Euclidean algorithm in `bigint-math.ts` rather than pull in a new package, matching this repo's one-dependency (`@noble/hashes`) TS philosophy.
- **Reused the existing Blake3 wrapper, extended for streaming.** `ts/src/dalos-blake3/index.ts` only exposed one-shot `blake3SumCustom` before; added `createBlake3XofStream`, a thin wrapper over `@noble/hashes/blake3.js`'s `.create().xof(n)`. Verified directly from the noble-hashes source (`_BLAKE3.writeInto` uses persistent instance state, `this.posOut`, across calls) *and* empirically (two chunked 16-byte `.xof()` calls concatenate to exactly the same bytes as one 32-byte one-shot `dkLen` call) that this is a genuine continuing stream, not a per-call reset — the same semantics as Go's `io.Reader`.
- **TS strict mode** (`noUncheckedIndexedAccess`) required non-null assertions on the two fixed-index byte-array writes in `candidate.ts`'s bit-fixing — matches the existing convention already used elsewhere in `ts/src/gen1/*.ts` for the same pattern.

**Byte-identity result:** `ts/tests/rsa4096/rsa4096.test.ts` loads `testvectors/v2_rsa4096.json` and asserts, for every vector, that the TS port reproduces `p`, `q`, `n`, `d`, `dp`, `dq`, `qi`, the entire JWK, the address, **and the exact `p_attempts`/`q_attempts` counts** — the last of these is the strongest possible signal: it proves the TS port consumes the seed stream in the *identical byte-for-byte pattern* as Go (including every rejection-sampling retry), not merely that it coincidentally lands on the same final numbers. All 5 tests (3 vectors + 2 sanity checks) pass, ~2 seconds per full key generation in Node's native BigInt — comparable to Go, not a meaningful performance regression.

Full existing TS suite re-run after the addition: **431/431 tests pass** across 20 files, zero regressions.

### 10.4 Documentation updated per `docs/ADDING_NEW_PRIMITIVES.md` Step 7

`CLAUDE.md` (Architecture tables for both Go and TS layouts, a new invariant, a Releases entry), `README.md` (new "Key Features" §4, repository-structure tree, testvectors listing), `testvectors/VALIDATION_LOG.md` (new dated run entry, matching the existing format). Registry adapter (playbook Step 8) deliberately skipped: the `CryptographicPrimitive` interface (`ts/src/registry/primitive.ts`) is EC-shaped (dual standard/smart addresses, an optional scalar) and RSA-4096 has neither — forcing the fit would be misleading, not helpful. Documented that reasoning inline in `ts/src/index.ts`'s re-export comment.

### 10.5 What's left before the live-chain test

Per the user's own stated plan: this package now needs to be wired into Codex's actual key-generation flow (a Codex-side task, using `@ouronet/dalos-crypto/rsa4096`'s `generateFromBitString`), then the user funds a real wallet and performs a live transfer between two addresses generated this way. Nothing in tonight's session touched a live network, a funded wallet, or Codex's own source — by design, matching the same "needs a human present" boundary from §9.5.
