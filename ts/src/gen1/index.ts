/**
 * DALOS Genesis (gen-1) TypeScript port — public surface.
 *
 * Phase 1 (v2.3.0): math foundation + coordinates + curve + point ops.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

// Math
export {
  Modular,
  ZERO,
  ONE,
  TWO,
  bytesToBigIntBE,
  bigIntToBytesBE,
  parseBase10,
} from './math.js';

// Coordinates
export type {
  CoordAffine,
  CoordExtended,
  CoordInverted,
  CoordProjective,
} from './coords.js';
export { INFINITY_POINT_EXTENDED } from './coords.js';

// Curve parameters + predicates
export type { Ellipse } from './curve.js';
export {
  DALOS_ELLIPSE,
  DALOS_FIELD,
  affine2Extended,
  extended2Affine,
  isInfinityPoint,
  isOnCurve,
  arePointsEqual,
  isInverseOnCurve,
} from './curve.js';

// Point operations
export type { PrecomputeMatrix } from './point-ops.js';
export {
  addition,
  additionV1,
  additionV2,
  additionV3,
  doubling,
  doublingV1,
  doublingV2,
  tripling,
  fortyNiner,
  precomputeMatrix,
} from './point-ops.js';

// Scalar multiplication (Phase 2)
export {
  BASE49_ALPHABET,
  digitValueBase49,
  bigIntToBase49,
  scalarMultiplier,
  scalarMultiplierWithGenerator,
  scalarMultiplierAsync,
} from './scalar-mult.js';

// Character matrix (Phase 3)
export {
  CHARACTER_MATRIX,
  CHARACTER_MATRIX_FLAT,
  STANDARD_ACCOUNT_PREFIX,
  SMART_ACCOUNT_PREFIX,
} from './character-matrix.js';

// Hashing + address encoding (Phase 3)
export {
  toUtf8Bytes,
  parseBigIntInBase,
  seedWordsToBitString,
  convertHashToBitString,
  affineToPublicKey,
  publicKeyToAffineCoords,
  dalosAddressComputer,
  convertToLetters,
  publicKeyToAddress,
  dalosAddressMaker,
  validateSeedWords,
  InvalidSeedWordsError,
  MIN_SEED_WORDS,
  MAX_SEED_WORDS,
  MIN_SEED_WORD_GLYPHS,
  MAX_SEED_WORD_GLYPHS,
} from './hashing.js';

// Bitmap input (Phase 4)
export type { Bitmap } from './bitmap.js';
export {
  BITMAP_ROWS,
  BITMAP_COLS,
  BITMAP_TOTAL_BITS,
  bitmapToBitString,
  bitStringToBitmapReveal,
  validateBitmap,
  parseAsciiBitmap,
  bitmapToAscii,
  equalBitmap,
} from './bitmap.js';

// Key generation API (Phase 4) — 6 input paths
export type {
  DalosKeyPair,
  DalosPrivateKey,
  DalosFullKey,
  BitStringValidation,
  PrivateKeyValidation,
} from './key-gen.js';
export {
  validateBitString,
  validatePrivateKey,
  generateRandomBitsOnCurve,
  generateScalarFromBitString,
  scalarToPrivateKey,
  scalarToPublicKey,
  scalarToKeyPair,
  fromRandom,
  fromBitString,
  fromIntegerBase10,
  fromIntegerBase49,
  fromSeedWords,
  fromBitmap,
} from './key-gen.js';

// AES encryption (Phase 5)
export {
  zeroBytes,
  bitStringToBytes,
  bytesToBitString,
  makeKeyFromPassword,
  encryptBitString,
  decryptBitString,
  encryptAndPad,
  decryptAndPadToLength,
} from './aes.js';

// Schnorr v2 signatures (Phase 6)
export type { SchnorrSignature } from './schnorr.js';
export {
  SCHNORR_HASH_DOMAIN_TAG,
  SCHNORR_NONCE_DOMAIN_TAG,
  bigIntBytesCanon,
  serializeSignature,
  parseSignature,
  schnorrHash,
  schnorrHashFromAffine,
  schnorrMessageDigest,
  deterministicNonce,
  schnorrSign,
  schnorrVerify,
  schnorrSignAsync,
  schnorrVerifyAsync,
} from './schnorr.js';
// F-MED-008 (v4.0.2): typed exception classes for the gen1 surface.
// Consumers catch by class via `instanceof` checks; see ./errors.ts
// docstring for the catch-by-class pattern.
export {
  InvalidBitStringError,
  InvalidBitmapError,
  InvalidPrivateKeyError,
  SchnorrSignError,
} from './errors.js';

// Ergonomic plain-string aliases (Phase 12 / v3.0.3+)
export {
  textToBitString,
  bitStringToText,
  sign,
  verify,
  encrypt,
  decrypt,
} from './aliases.js';
