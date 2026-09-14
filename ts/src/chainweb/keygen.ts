/**
 * Deterministic Ed25519 key generation for Kadena/Chainweb `k:` accounts
 * from an arbitrary DALOS seed bitstring -- the "Stoic path". Mirrors
 * `Chainweb/keygen.go` exactly; see that file's doc comment for the full
 * design.
 *
 * Uses `@noble/curves`'s ed25519 (the same "noble" family as this
 * package's existing `@noble/hashes` dependency, and the same trust tier
 * already relied on elsewhere in the wider workspace for Kadena key
 * derivation) for the actual RFC 8032 math -- not hand-rolled, exactly
 * like the Go side deliberately uses stdlib `crypto/ed25519` rather than
 * reimplementing Ed25519 point arithmetic from scratch.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { newSeedStream } from './stream.js';

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * The complete output of one Stoic-path derivation: a real,
 * standards-compliant Ed25519 keypair plus the Chainweb `k:` account name
 * it corresponds to. Mirrors Go's KeyGenResult field-for-field.
 */
export interface ChainwebKeyGenResult {
  /** The original DALOS seed bitstring this was derived from. */
  seed: string;
  /** The position (0, 1, 2, ... -- infinitely many independent accounts per seed). */
  index: number;
  /** The 32-byte Ed25519 seed (RFC 8032) -- store/export this as the private key. */
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  /** "k:" + lowercase-hex(publicKey) -- a real, spendable Chainweb k: account name. */
  address: string;
}

/**
 * Derives Chainweb account #0 (the default/primary account) from a DALOS
 * seed bitstring. Equivalent to `generateFromBitStringAtIndex(seed, 0)`.
 */
export function generateFromBitString(seedBitString: string): ChainwebKeyGenResult {
  return generateFromBitStringAtIndex(seedBitString, 0);
}

/**
 * Derives Chainweb account #index from the same seed bitstring that
 * produces account #0 -- any index directly reachable without generating
 * the ones before it (pure function of (seed, index), no chained state --
 * mirrors RSA4096's indexed generation and Go's identical function here).
 */
export function generateFromBitStringAtIndex(
  seedBitString: string,
  index: number,
): ChainwebKeyGenResult {
  const stream = newSeedStream(seedBitString, index);
  const seed = stream.read(32);

  const { secretKey, publicKey } = ed25519.keygen(seed);

  return {
    seed: seedBitString,
    index,
    privateKey: secretKey,
    publicKey,
    address: `k:${bytesToHex(publicKey)}`,
  };
}

/**
 * Signs and verifies a fixed test message under the given result's
 * keypair, using `@noble/curves`'s own sign/verify -- an independent
 * round-trip proof that the derived key is a genuinely usable Ed25519
 * keypair. Mirrors Go's SelfCheckEd25519.
 */
export function selfCheckEd25519(r: ChainwebKeyGenResult): void {
  const message = new TextEncoder().encode('DALOS_Crypto Chainweb Stoic-path self-check');
  const sig = ed25519.sign(message, r.privateKey);
  if (!ed25519.verify(sig, message, r.publicKey)) {
    throw new Error(
      'Chainweb: self-check FAILED -- signature did not verify under the derived public key',
    );
  }
}
