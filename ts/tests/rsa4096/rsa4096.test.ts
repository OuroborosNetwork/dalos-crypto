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
import { generateFromBitString, selfCheckTextbookRSA } from '../../src/rsa4096/index.js';

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
