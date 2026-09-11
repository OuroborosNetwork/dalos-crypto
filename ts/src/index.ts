/**
 * @ouronet/dalos-crypto — TypeScript port of the DALOS Genesis cryptographic primitive.
 *
 * Phase 1 landed (v2.3.0): Genesis math foundation is now exported.
 * Phase 2 onward adds scalar multiplication, hashing, key generation,
 * AES, Schnorr, and the modular primitive registry.
 *
 * @see ../../docs/TS_PORT_PLAN.md
 */

// Re-export the gen1 subpath at the top level for discoverability.
// Canonical import path is still `@ouronet/dalos-crypto/gen1`.
export * as gen1 from './gen1/index.js';

// Re-export the registry subpath — the idiomatic entry point for
// consumers who want to work at the primitive-registry level rather
// than calling gen1 functions directly.
export * as registry from './registry/index.js';

// Re-export the historical-curves subpath at the top level for discoverability.
// Canonical import path is still `@ouronet/dalos-crypto/historical`. The three production
// primitives (LETO / ARTEMIS / APOLLO) are exposed but NOT auto-registered in `createDefaultRegistry()` — see `ts/src/historical/index.ts:20-24`.
export * as historical from './historical/index.js';

// Re-export the dalos-blake3 subpath at the top level for discoverability.
// Canonical import path is still `@ouronet/dalos-crypto/dalos-blake3`. Exposes `blake3SumCustom`
// and `sevenFoldBlake3` — the Genesis seven-fold construction. This subpath WILL be extracted to a sibling npm package in Phase 11; the root namespace re-export is a forward-compatible alias.
//
// F-LOW-004 (audit cycle 2026-05-04, v4.0.3): both `blake3` and `dalosBlake3`
// are exported. `dalosBlake3` mirrors the subpath name (`./dalos-blake3`) and
// is the recommended alias going forward — IDE auto-import on `blake3` was
// ambiguous against `@noble/hashes/blake3` and other competing libraries in
// monorepo / multi-dep contexts. The original `blake3` alias is retained for
// back-compat (it has been on the public API since v2.3.0); future major may
// retire it.
export * as dalosBlake3 from './dalos-blake3/index.js';
export * as blake3 from './dalos-blake3/index.js';

// Re-export the rsa4096 subpath at the top level for discoverability.
// Canonical import path is still `@ouronet/dalos-crypto/rsa4096`. Deterministic
// RSA-4096 key generation from a DALOS seed bitstring, for Arweave account
// derivation. NOT registered in the `registry` CryptographicPrimitive
// interface -- that interface is EC-shaped (dual standard/smart addresses,
// an optional scalar); RSA-4096 has none of that (a single Arweave-style
// address, no scalar, JWK-shaped key material), so forcing it into that
// shape would be misleading rather than helpful. See
// docs/ADDING_NEW_PRIMITIVES.md Step 8 and
// /.docs/deterministic-rsa4096-from-seed.md for the reasoning.
export * as rsa4096 from './rsa4096/index.js';
