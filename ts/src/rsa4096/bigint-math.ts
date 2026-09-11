/**
 * Shared arbitrary-precision integer helpers for the RSA4096 port. Native
 * `BigInt` has no built-in modular exponentiation, gcd, or modular
 * inverse -- Go's `math/big.Int` provides all three (`Exp`, `GCD`,
 * `ModInverse`), so this file hand-rolls the TypeScript equivalents rather
 * than pull in a new dependency (this repo's TS side has exactly one
 * runtime dependency, `@noble/hashes` -- see CLAUDE.md).
 *
 * Every function here is a well-known, textbook algorithm (square-and-
 * multiply modexp, the extended Euclidean algorithm) -- deliberately
 * boring and easy to verify by reading, which matters for a port whose
 * whole point is "must produce byte-identical output to the Go reference,
 * forever."
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

/** Converts a big-endian byte array to a non-negative BigInt. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return BigInt(hex);
}

/**
 * Converts a non-negative BigInt to its minimal big-endian byte
 * representation -- matching Go's `big.Int.Bytes()`: no sign, no leading
 * zero byte, and a value of 0 produces an EMPTY slice (mirrored here
 * exactly, including that edge case, since jwk.ts relies on it never
 * needing special-casing).
 */
export function bigIntToBytes(n: bigint): Uint8Array {
  if (n < 0n) {
    throw new RangeError('bigIntToBytes: negative values are not supported');
  }
  if (n === 0n) {
    return new Uint8Array(0);
  }
  let hex = n.toString(16);
  if (hex.length % 2 === 1) {
    hex = `0${hex}`;
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Modular exponentiation via square-and-multiply: base^exponent mod modulus. */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

/** Greatest common divisor via the Euclidean algorithm. Inputs must be >= 0. */
export function gcd(a: bigint, b: bigint): bigint {
  let x = a;
  let y = b;
  while (y !== 0n) {
    [x, y] = [y, x % y];
  }
  return x < 0n ? -x : x;
}

/**
 * Modular inverse via the extended Euclidean algorithm: returns x such that
 * (a * x) mod m === 1, or `null` if no inverse exists (gcd(a, m) !== 1) --
 * mirroring Go's `big.Int.ModInverse`, which returns `nil` in that case.
 * `m` must be positive; the result is always in `[0, m)`.
 */
export function modInverse(a: bigint, m: bigint): bigint | null {
  if (m <= 0n) {
    throw new RangeError('modInverse: modulus must be positive');
  }
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }

  if (oldR !== 1n) {
    return null; // gcd(a, m) != 1 -- no inverse exists.
  }
  return ((oldS % m) + m) % m;
}
