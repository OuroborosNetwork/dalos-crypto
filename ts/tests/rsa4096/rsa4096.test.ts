/**
 * Byte-identity test: loads the Go-reference-produced corpus at
 * ../../testvectors/v2_rsa4096.json and asserts the TypeScript port
 * reproduces every field of every vector exactly. This is the
 * cross-language correctness assertion the whole RSA4096 port exists to
 * satisfy -- see docs/ADDING_NEW_PRIMITIVES.md Step 4/5.
 *
 * Full RSA-4096 key generation from scratch (finding two 2048-bit primes)
 * is inherently a few seconds of work per vector -- see the corpus
 * generator's own comment on why it's kept to 3 vectors. This suite pays
 * that cost 3 times, not more.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  type ProgressEvent,
  generateFromBitString,
  generateFromBitStringAsync,
  selfCheckTextbookRSA,
  validateSeedBitString,
} from '../../src/rsa4096/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const corpusPath = resolve(here, '..', '..', '..', 'testvectors', 'v2_rsa4096.json');

interface RSA4096JWKVector {
  readonly kty: string;
  readonly n: string;
  readonly e: string;
  readonly d: string;
  readonly p: string;
  readonly q: string;
  readonly dp: string;
  readonly dq: string;
  readonly qi: string;
}

interface RSA4096Vector {
  readonly id: string;
  readonly source: string;
  readonly input_bitstring: string;
  readonly input_words?: readonly string[];
  readonly prime_p_hex: string;
  readonly prime_q_hex: string;
  readonly modulus_n_hex: string;
  readonly private_exponent_d_hex: string;
  readonly dp_hex: string;
  readonly dq_hex: string;
  readonly qi_hex: string;
  readonly jwk: RSA4096JWKVector;
  readonly address: string;
  readonly p_attempts: number;
  readonly q_attempts: number;
}

interface RSA4096Corpus {
  readonly schema_version: number;
  readonly miller_rabin_rounds: number;
  readonly small_prime_count: number;
  readonly rsa4096_vectors: readonly RSA4096Vector[];
}

function loadCorpus(): RSA4096Corpus {
  const raw = readFileSync(corpusPath, 'utf-8');
  return JSON.parse(raw) as RSA4096Corpus;
}

describe('RSA4096 corpus byte-identity', () => {
  const corpus = loadCorpus();

  it('corpus is non-empty and has the expected schema', () => {
    expect(corpus.schema_version).toBe(1);
    expect(corpus.rsa4096_vectors.length).toBeGreaterThan(0);
  });

  // MILLER_RABIN_ROUNDS and SMALL_PRIME_COUNT drift would silently change
  // how many stream bytes get consumed per candidate -- catch it here
  // rather than as a mysterious later byte-identity failure.
  it('constants match the Go reference exactly', async () => {
    const { MILLER_RABIN_ROUNDS, SMALL_PRIME_COUNT } = await import('../../src/rsa4096/index.js');
    expect(MILLER_RABIN_ROUNDS).toBe(corpus.miller_rabin_rounds);
    expect(SMALL_PRIME_COUNT).toBe(corpus.small_prime_count);
  });

  for (const vector of corpus.rsa4096_vectors) {
    it(`${vector.id}: reproduces every field exactly`, () => {
      const result = generateFromBitString(vector.input_bitstring);

      expect(result.p.toString(16)).toBe(vector.prime_p_hex);
      expect(result.q.toString(16)).toBe(vector.prime_q_hex);
      expect(result.key.n.toString(16)).toBe(vector.modulus_n_hex);
      expect(result.key.d.toString(16)).toBe(vector.private_exponent_d_hex);
      expect(result.key.dp.toString(16)).toBe(vector.dp_hex);
      expect(result.key.dq.toString(16)).toBe(vector.dq_hex);
      expect(result.key.qi.toString(16)).toBe(vector.qi_hex);

      expect(result.jwk).toEqual(vector.jwk);
      expect(result.address).toBe(vector.address);

      // The attempt counts are a strong signal that the stream-consumption
      // pattern (candidate draws + witness draws, including rejection
      // sampling) is byte-for-byte identical to Go, not just "happens to
      // land on the same final primes."
      expect(result.pAttempts).toBe(vector.p_attempts);
      expect(result.qAttempts).toBe(vector.q_attempts);

      // Independent correctness check, not dependent on the corpus.
      expect(() => selfCheckTextbookRSA(result.key)).not.toThrow();
    });
  }
});

describe('RSA4096 progress reporting -- for building a UI progress bar', () => {
  // Reuse the corpus's own first seed rather than a fresh one, so this
  // describe block doesn't pay for a 4th independent full generation.
  const corpus = loadCorpus();
  const seed = corpus.rsa4096_vectors[0]!.input_bitstring;

  function assertValidEventStream(
    events: ProgressEvent[],
    pAttempts: number,
    qAttempts: number,
  ): void {
    expect(events.length).toBeGreaterThan(0);
    const lastAttemptsInStage: Record<string, number> = {};
    let sawP = false;
    let sawQ = false;
    for (const ev of events) {
      expect(['p', 'q']).toContain(ev.stage);
      if (ev.stage === 'p') sawP = true;
      if (ev.stage === 'q') sawQ = true;

      const prev = lastAttemptsInStage[ev.stage] ?? 0;
      expect(ev.attempts).toBeGreaterThan(prev); // strictly increasing within a stage
      lastAttemptsInStage[ev.stage] = ev.attempts;

      expect(ev.stageProgress).toBeGreaterThanOrEqual(0);
      expect(ev.stageProgress).toBeLessThan(1);
      expect(ev.overallProgress).toBeGreaterThanOrEqual(0);
      expect(ev.overallProgress).toBeLessThan(1);
      const wantOverall = ev.stage === 'q' ? 0.5 + ev.stageProgress / 2 : ev.stageProgress / 2;
      expect(ev.overallProgress).toBeCloseTo(wantOverall, 12);
    }
    expect(sawP).toBe(true);
    expect(sawQ).toBe(true);
    expect(lastAttemptsInStage.p).toBe(pAttempts);
    expect(lastAttemptsInStage.q).toBe(qAttempts);
  }

  it('sync generateFromBitString reports a valid, usable progress stream', () => {
    const events: ProgressEvent[] = [];
    const result = generateFromBitString(seed, (ev) => events.push(ev));
    assertValidEventStream(events, result.pAttempts, result.qAttempts);
  });

  it('a progress callback never changes the output (purely observational)', () => {
    const withCallback = generateFromBitString(seed, () => {});
    const withoutCallback = generateFromBitString(seed);
    expect(withCallback.key.n).toBe(withoutCallback.key.n);
    expect(withCallback.key.d).toBe(withoutCallback.key.d);
    expect(withCallback.pAttempts).toBe(withoutCallback.pAttempts);
    expect(withCallback.qAttempts).toBe(withoutCallback.qAttempts);
  });

  it('async generateFromBitStringAsync produces byte-identical output to the sync path, plus a valid progress stream', async () => {
    const events: ProgressEvent[] = [];
    const asyncResult = await generateFromBitStringAsync(seed, (ev) => events.push(ev));
    const syncResult = generateFromBitString(seed);

    expect(asyncResult.key.n).toBe(syncResult.key.n);
    expect(asyncResult.key.d).toBe(syncResult.key.d);
    expect(asyncResult.address).toBe(syncResult.address);
    assertValidEventStream(events, asyncResult.pAttempts, asyncResult.qAttempts);
  });
});

describe('RSA4096 seed length is gated to exactly the two blessed curve lengths', () => {
  // Settled 2026-09-11: the earlier "any length >= 128" floor was
  // tightened to a closed allow-list -- see stream.ts's
  // ALLOWED_SEED_BIT_STRING_LENGTHS doc comment for the reasoning (RSA
  // security comes from the 2048-bit prime search space, not seed
  // length; gating to exactly {1024, 1600} ties every RSA seed to one of
  // the two curves' own already-validated pipelines, instead of an
  // open-ended, unaudited "any custom string" input path).
  it('accepts a 1024-bit (APOLLO-shaped) seed and produces a valid key', () => {
    const apolloSeed = '10'.repeat(512); // 1024 characters of '0'/'1'
    expect(apolloSeed.length).toBe(1024);

    const result = generateFromBitString(apolloSeed);
    expect(result.key.n.toString(2).length).toBe(4096);
    expect(result.address.length).toBe(43);
    expect(() => selfCheckTextbookRSA(result.key)).not.toThrow();
  });

  it('rejects a seed shorter than 1024', () => {
    expect(() => validateSeedBitString('01'.repeat(63))).toThrow(); // 126 chars
  });

  it('rejects lengths strictly between 1024 and 1600', () => {
    expect(() => validateSeedBitString('0'.repeat(1300))).toThrow();
  });

  it('rejects other DALOS_Crypto curves\' safe-scalar lengths (LETO 545, ARTEMIS 1023)', () => {
    expect(() => validateSeedBitString('0'.repeat(545))).toThrow();
    expect(() => validateSeedBitString('0'.repeat(1023))).toThrow();
  });

  it('rejects an arbitrary long custom string (65536 chars) -- no unbounded input path', () => {
    expect(() => validateSeedBitString('01'.repeat(32768))).toThrow();
  });

  it('rejects one bit over each blessed length', () => {
    expect(() => validateSeedBitString('0'.repeat(1025))).toThrow();
    expect(() => validateSeedBitString('0'.repeat(1601))).toThrow();
  });
});
