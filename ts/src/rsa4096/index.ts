/**
 * @ouronet/dalos-crypto/rsa4096
 *
 * Deterministic RSA-4096 key generation from an arbitrary DALOS seed
 * bitstring -- a real, standards-compliant, fully usable RSA-4096 keypair
 * (the format Arweave wallets require), such that the same seed always
 * regenerates the exact same keypair, byte-for-byte, forever, on any
 * machine.
 *
 * This is the TypeScript port of the Go `RSA4096` package (root
 * `RSA4096/`), validated byte-for-byte against its test-vector corpus
 * (`testvectors/v2_rsa4096.json`) in `ts/tests/rsa4096/`. See
 * /.docs/deterministic-rsa4096-from-seed.md for the full design history.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

export {
  newSeedStream,
  validateSeedBitString,
  ALLOWED_SEED_BIT_STRING_LENGTHS,
} from './stream.js';
export { generateCandidate, CANDIDATE_BITS, CANDIDATE_BYTES } from './candidate.js';
export { passesTrialDivision, SMALL_PRIME_COUNT } from './primes.js';
export { isProbablyPrime, MILLER_RABIN_ROUNDS } from './millerrabin.js';
export {
  findPrime,
  findPrimeAsync,
  findTwoPrimes,
  findTwoPrimesAsync,
  passesAuxiliaryConstraints,
  PUBLIC_EXPONENT,
} from './primesearch.js';
export type { FindPrimeResult, FindTwoPrimesResult } from './primesearch.js';
export type { ProgressCallback, ProgressEvent, ProgressStage } from './progress.js';
export { STAGE_SEARCHING_P, STAGE_SEARCHING_Q } from './progress.js';
export { assembleKey } from './keyassembly.js';
export type { RSAKey } from './keyassembly.js';
export { toJWK, addressOf, ARWEAVE_MODULUS_BYTES } from './jwk.js';
export type { JWK } from './jwk.js';
export {
  generateFromBitString,
  generateFromBitStringAsync,
  selfCheckTextbookRSA,
} from './pipeline.js';
export type { KeyGenResult } from './pipeline.js';
export {
  generateFromBitStringAtIndex,
  generateFromBitStringAtIndexAsync,
  deriveIndexedSeedBitString,
  MAX_INDEX,
} from './indexed.js';
export {
  generateBatchFromBitString,
  generateBatchFromBitStringAsync,
  BatchRangeError,
  BatchGenerationError,
} from './batch.js';
export type { BatchProgressEvent, BatchProgressCallback, BatchResultCallback } from './batch.js';
