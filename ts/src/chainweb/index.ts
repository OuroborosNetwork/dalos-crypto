/**
 * Chainweb / "Stoic path" — deterministic Ed25519 key generation for
 * Kadena/Chainweb `k:` accounts from an arbitrary DALOS seed bitstring.
 * See `Chainweb/stream.go` and `Chainweb/keygen.go` (Go reference) for the
 * full design.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

export {
  type ChainwebKeyGenResult,
  generateFromBitString,
  generateFromBitStringAtIndex,
  selfCheckEd25519,
} from './keygen.js';
export { ALLOWED_SEED_BIT_STRING_LENGTHS, newSeedStream, validateSeedBitString } from './stream.js';
