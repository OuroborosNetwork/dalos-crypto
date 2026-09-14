# The Stoic Path: deterministic Chainweb (Kadena) addresses from a DALOS seed

**Status:** shipped, `v4.5.0`. Go: `Chainweb/`. TypeScript: `@ouronet/dalos-crypto/chainweb`.

## What this is, in one sentence

The same DALOS seed bitstring that already produces your Genesis EC identity
(`Ѻ.`/`Σ.`) and, via `rsa4096`, an Arweave address, now *also* produces a
real, standards-compliant, spendable Kadena/Chainweb `k:` account — with
infinitely many independent positions from one seed, and no separate
12/24-word Kadena-specific mnemonic required.

## Why this exists

Kadena's ecosystem already has three wallet-compatible ways to turn a
mnemonic into a Chainweb account — Koala, Chainweaver, and EckoWallet. All
three were investigated directly (source code read, not assumed) before
this was built:

| Wallet | Dictionary | Derivation |
|---|---|---|
| Koala | Standard BIP39 English (2048 words) | Real SLIP-0010 Ed25519 HD derivation → `m'/44'/626'/index'` |
| Chainweaver | Standard BIP39 English (same list) | Cardano's legacy BIP32-Ed25519 scheme (`cardano-crypto.js`) — flat hardened index off root |
| EckoWallet | Identical to Chainweaver | Identical to Chainweaver — same code, no divergence anywhere |

Two things fell out of that investigation that motivate this document:

1. **Chainweaver and EckoWallet are not two things.** They're the same
   derivation, same dictionary, same code path, confirmed both in this
   repo's own vendored `kadena-stoic-legacy` and independently in a
   third-party tool (`Eucalyptus-Labs/KadenaKeys`, which doesn't even have
   a separate Chainweaver implementation file — its own UI's Chainweaver
   option routes to the Ecko deriver). Treating them as two options
   anywhere in this codebase or in Codex's UI is presenting one thing
   as two.
2. **None of the three require a fixed dictionary at the protocol level.**
   BIP39's wordlist is purely a UI encoding layer over entropy — the actual
   Chainweb account name is fixed by Pact's own convention
   (`"k:" + lowercase-hex(publicKey)`), completely independent of how the
   underlying Ed25519 key was derived. Nothing about Chainweb *requires*
   a 12/24-word checksummed mnemonic specifically.

Given (2), and given this repo already has a validated, audited,
seed-to-bitstream pipeline (`SeedWordsToBitString` — 1-256 words, any
glyph from the 256-glyph DALOS `CharacterMatrix`, no fixed dictionary),
the natural fourth option isn't "yet another 12/24-word BIP39-style
dictionary" — it's "reuse the seed you already have."

## What "Stoic path" means concretely

**No new dictionary.** No new word list to memorize, back up, or lose.
Whatever seed words already produce your DALOS EC identity and your
Arweave addresses now *also* produce a Chainweb account, deterministically,
forever, for free.

This is a deliberate one-word overload worth being precise about: "Stoic
path" refers to the *reuse of the flexible DALOS seed-word scheme* for
Chainweb specifically — not a new fixed dictionary of Stoic-philosophy
vocabulary. (A separate fixed-dictionary "Stoic wordlist" option, matching
Koala's shape more literally, was discussed and remains a possible future
addition — see "What this document does NOT cover" below. What shipped in
`v4.5.0` is the seed-reuse path.)

## The pipeline, step by step

```
Seed words (1-256 words, DALOS CharacterMatrix charset)
  │
  │  ValidateSeedWords + SeedWordsToBitString (existing, frozen, unchanged)
  ▼
1600-bit (DALOS) or 1024-bit (APOLLO) seed bitstring
  │
  │  Blake3 XOF, domain tag "DALOS-gen1/ChainwebEd25519Stream/v1"
  │  (distinct from the EC path's own tag and from
  │  "DALOS-gen1/RSA4096Stream/v1" — cannot collide with or leak
  │  anything about either)
  │  Position index folded into the SAME hash input, so every
  │  index (0, 1, 2, ...) is a pure function of (seed, index),
  │  no chained state, any index directly reachable
  ▼
32 bytes
  │
  │  Standard Ed25519 key generation (Go: stdlib crypto/ed25519;
  │  TS: @noble/curves) — NOT hand-rolled curve math. This is the
  │  one place a real, audited off-the-shelf implementation is used
  │  rather than this repo's own arithmetic, deliberately: Ed25519
  │  point arithmetic is exactly the kind of thing not worth
  │  reimplementing.
  ▼
Ed25519 keypair (32-byte private seed, 32-byte public key)
  │
  │  "k:" + lowercase-hex(publicKey) — Pact/Chainweb's own fixed
  │  protocol convention, not a design choice this package makes.
  │  Verified directly against real derived accounts before
  │  implementation.
  ▼
A real, spendable Chainweb k: account
```

## What's free to design, and what isn't (the question that led here)

Three distinct layers, three different amounts of freedom:

1. **Words → seed bytes.** Completely free. Chainweb has zero awareness
   that mnemonics exist — it never sees a word. Dictionary size, actual
   words, checksum scheme (or none), the KDF used — all wallet-side UX,
   invisible to the chain. DALOS's own scheme (arbitrary charset, no fixed
   dictionary, Blake3-based) is one valid choice among many here; BIP39 is
   another.
2. **Seed bytes → keypair.** Mostly free (path structure, tree depth,
   hardened/non-hardened — all convention), with exactly one hard
   constraint: whatever comes out has to be a legitimate Ed25519 private
   scalar + public key per RFC 8032. Not a Chainweb-specific rule — just
   what "a real Ed25519 key" is, and it applies here only because Chainweb
   itself chose Ed25519 as its signature scheme.
3. **Public key → address.** Zero freedom. `"k:" + lowercase-hex(pubkey)`
   is fixed by Pact/Chainweb's own protocol, enforced identically by every
   node on the network. This is the one place "we could design it
   differently" stops being a meaningful sentence.

The Stoic path exercises full freedom at layer 1 (DALOS's seed-word
scheme, not BIP39), a specific standards-compliant choice at layer 2
(SLIP-0010-flavored: real, off-the-shelf Ed25519, not a custom scalar
derivation), and the mandatory convention at layer 3.

## Domain separation — why three completely different outputs from one seed can never collide

| Path | Domain tag | Produces |
|---|---|---|
| EC identity (Gen-1) | (curve-native derivation, not a Blake3 domain tag) | `Ѻ.`/`Σ.` DALOS Genesis address |
| Arweave (`rsa4096`) | `DALOS-gen1/RSA4096Stream/v1` | RSA-4096 keypair → Arweave address |
| Chainweb (`chainweb`) | `DALOS-gen1/ChainwebEd25519Stream/v1` | Ed25519 keypair → `k:` account |

Each stream is seeded from `Blake3(domain_tag ‖ seed_bitstring ‖ ...)` with
a distinct tag. Knowing one derived output reveals nothing about the
others, structurally — not by obscurity, by construction.

## Multiple independent Chainweb accounts from one seed

```go
addr0, _ := chainweb.GenerateFromBitString(seedBitString)                    // account #0
addr7, _ := chainweb.GenerateFromBitStringAtIndex(seedBitString, 7)          // account #7, directly, no need to generate 0-6 first
```

```ts
const addr0 = generateFromBitString(seedBitString);
const addr7 = generateFromBitStringAtIndex(seedBitString, 7);
```

Every index is a pure function of `(seed, index)` — same design principle
as `rsa4096`'s indexed/batch/ranges generation. No BIP32-style parent/child
relationship, no chained derivation, no need to walk from 0 to reach 7.

## Cross-language guarantee

Go is the canonical reference. TypeScript is verified byte-identical
against a frozen corpus (`testvectors/v4_chainweb_ed25519.json`, 6
vectors) — private key, public key, and address match exactly for every
vector, including a real seed-words-derived case and both the 1024-bit
(APOLLO) and 1600-bit (DALOS) seed lengths. See
`ts/tests/chainweb/chainweb-corpus.test.ts`.

## What this document does NOT cover

- **A fixed-dictionary "Stoic wordlist"** (a genuinely new, curated
  2048-word list, BIP39-shaped, usable the way Koala's English list is) —
  discussed as a design option, not built. Would be a separate,
  additional entry point (something like
  `generateFromCustomMnemonic(words, wordlist)`), not a replacement for
  the seed-reuse path this document describes. Revisit if a
  Koala-shaped UX (fresh 12/24-word Kadena-only wallet, no DALOS identity
  involved) is wanted alongside this.
- **Unifying Chainweaver/EckoWallet into one UI option.** That's a
  consumer-side (Codex) change, not something this library needs to do —
  see `ouronet-libs/HANDOFF-chainweb-stoic-path-and-wallet-unification.md`
  (a different repo — `OuroborosNetwork/_libs/ouronet-libs`, not here).
- **Watch-only / non-hardened public-key derivation.** Deliberately out of
  scope — SLIP-0010-style Ed25519 (what this package uses) cannot support
  it structurally. If that capability is ever needed, it requires
  Cardano's more involved BIP32-Ed25519 construction instead (see the
  Chainweaver/Ecko row above) — a materially bigger build, not a small
  addition to this one.

## Source

- Go: `Chainweb/stream.go`, `Chainweb/keygen.go`, `Chainweb/chainweb_test.go`
- TypeScript: `ts/src/chainweb/stream.ts`, `ts/src/chainweb/keygen.ts`, `ts/src/chainweb/index.ts`
- Frozen corpus: `testvectors/v4_chainweb_ed25519.json`
- Generator: `testvectors/generator/main.go`'s `generateChainweb()`
- CI pin: `.github/workflows/go-ci.yml`'s `BASELINES` array
