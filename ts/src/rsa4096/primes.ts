/**
 * Cheap trial-division bouncer. Direct port of RSA4096/primes.go -- see
 * that file's doc comment for the cost-model derivation of why 2000 small
 * primes is the right cutoff, and why the list is computed via a sieve at
 * call time rather than hardcoded (cross-language safety: a sieve
 * algorithm is trivial to write identically in Go and TS; two
 * independently-maintained 2000-entry literal arrays are a realistic
 * place for the two to silently drift).
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

/** Matches RSA4096/primes.go's smallPrimeCount exactly. */
export const SMALL_PRIME_COUNT = 2000;

/** Sieve of Eratosthenes: every prime <= limit, in increasing order. */
function sieveOfEratosthenes(limit: number): number[] {
  if (limit < 2) return [];
  const isComposite = new Uint8Array(limit + 1);
  const primes: number[] = [];
  for (let i = 2; i <= limit; i++) {
    if (isComposite[i]) continue;
    primes.push(i);
    for (let j = i * i; j <= limit; j += i) {
      isComposite[j] = 1;
    }
  }
  return primes;
}

/**
 * Returns the first `n` odd primes (2 is excluded on purpose -- every
 * candidate from generateCandidate is odd by construction, so testing
 * divisibility by 2 can never reject anything). Matches
 * RSA4096/primes.go's smallOddPrimes exactly, including the doubling
 * grow-and-resieve strategy.
 */
function smallOddPrimes(n: number): number[] {
  if (n <= 0) return [];

  let bound = 1000;
  for (;;) {
    const primes = sieveOfEratosthenes(bound);
    const odd = primes.filter((p) => p !== 2);
    if (odd.length >= n) {
      return odd.slice(0, n);
    }
    bound *= 2;
  }
}

/** Computed once (the sieve is cheap, but no reason to redo it per candidate). */
const smallOddPrimesCache: bigint[] = smallOddPrimes(SMALL_PRIME_COUNT).map((p) => BigInt(p));

/**
 * Reports whether `candidate` is NOT divisible by any of the first
 * {@link SMALL_PRIME_COUNT} odd primes. Matches RSA4096/primes.go's
 * PassesTrialDivision exactly.
 */
export function passesTrialDivision(candidate: bigint): boolean {
  for (const p of smallOddPrimesCache) {
    if (candidate % p === 0n) {
      return false;
    }
  }
  return true;
}
