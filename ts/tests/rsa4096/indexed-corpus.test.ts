/**
 * Byte-identity test: loads the Go-reference-produced corpus at
 * ../../testvectors/v3_rsa4096_indexed.json and asserts the TypeScript
 * port reproduces every field of every vector exactly, via
 * generateFromBitStringAtIndex -- this is the cross-language correctness
 * assertion the indexed/batch-generation feature exists to satisfy.
 *
 * rsa4096-idx-01/02/03 share ONE seed at indices 0, 1, 2 -- besides
 * proving indexed generation itself, they ALSO double as the frozen
 * cross-check for generateBatchFromBitString (see the dedicated describe
 * block below): batching is pure orchestration over indexed generation,
 * not a separate derivation, so batch(seed, 0, 3) must reproduce these
 * three vectors exactly.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  generateBatchFromBitStringAsync,
  generateFromBitStringAtIndex,
  generateFromBitStringAtRangesAsync,
  selfCheckTextbookRSA,
} from '../../src/rsa4096/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const corpusPath = resolve(here, '..', '..', '..', 'testvectors', 'v3_rsa4096_indexed.json');

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

interface RSA4096IndexedVector {
  readonly id: string;
  readonly source: string;
  readonly input_bitstring: string;
  readonly input_words?: readonly string[];
  readonly index: number;
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

interface RSA4096IndexedCorpus {
  readonly schema_version: number;
  readonly miller_rabin_rounds: number;
  readonly small_prime_count: number;
  readonly rsa4096_indexed_vectors: readonly RSA4096IndexedVector[];
}

function loadCorpus(): RSA4096IndexedCorpus {
  const raw = readFileSync(corpusPath, 'utf-8');
  return JSON.parse(raw) as RSA4096IndexedCorpus;
}

describe('RSA4096 indexed corpus byte-identity', () => {
  const corpus = loadCorpus();

  it('corpus is non-empty and has the expected schema', () => {
    expect(corpus.schema_version).toBe(1);
    expect(corpus.rsa4096_indexed_vectors.length).toBe(6);
  });

  for (const vector of corpus.rsa4096_indexed_vectors) {
    it(`${vector.id}: reproduces every field exactly (index ${vector.index})`, () => {
      const result = generateFromBitStringAtIndex(vector.input_bitstring, vector.index);

      expect(result.p.toString(16)).toBe(vector.prime_p_hex);
      expect(result.q.toString(16)).toBe(vector.prime_q_hex);
      expect(result.key.n.toString(16)).toBe(vector.modulus_n_hex);
      expect(result.key.d.toString(16)).toBe(vector.private_exponent_d_hex);
      expect(result.key.dp.toString(16)).toBe(vector.dp_hex);
      expect(result.key.dq.toString(16)).toBe(vector.dq_hex);
      expect(result.key.qi.toString(16)).toBe(vector.qi_hex);

      expect(result.jwk).toEqual(vector.jwk);
      expect(result.address).toBe(vector.address);

      expect(result.pAttempts).toBe(vector.p_attempts);
      expect(result.qAttempts).toBe(vector.q_attempts);

      expect(() => selfCheckTextbookRSA(result.key)).not.toThrow();
    });
  }
});

describe('generateBatchFromBitString reproduces the frozen idx-01/02/03 vectors', () => {
  // Uses the Async variant (yields every 8 candidate draws) rather than
  // chaining 3 full sync generations with zero internal yield points --
  // see batch.test.ts's header comment for why: a long enough
  // uninterrupted synchronous block can miss vitest's own internal
  // worker-RPC heartbeat (a 60s birpc default, not configurable via
  // vitest.config.ts), which is a false-positive infrastructure failure
  // distinct from any real assertion failing.
  it('batch(seed, 0, 3) matches rsa4096-idx-01/02/03 exactly', async () => {
    const corpus = loadCorpus();
    const v01 = corpus.rsa4096_indexed_vectors.find((v) => v.id === 'rsa4096-idx-01')!;
    const v02 = corpus.rsa4096_indexed_vectors.find((v) => v.id === 'rsa4096-idx-02')!;
    const v03 = corpus.rsa4096_indexed_vectors.find((v) => v.id === 'rsa4096-idx-03')!;
    expect(v01.input_bitstring).toBe(v02.input_bitstring);
    expect(v01.input_bitstring).toBe(v03.input_bitstring);

    const batch = await generateBatchFromBitStringAsync(v01.input_bitstring, 0, 3);

    expect(batch[0]!.address).toBe(v01.address);
    expect(batch[1]!.address).toBe(v02.address);
    expect(batch[2]!.address).toBe(v03.address);
    expect(batch[0]!.key.n.toString(16)).toBe(v01.modulus_n_hex);
    expect(batch[1]!.key.n.toString(16)).toBe(v02.modulus_n_hex);
    expect(batch[2]!.key.n.toString(16)).toBe(v03.modulus_n_hex);
  }, 60_000);
});

describe('generateFromBitStringAtRanges reproduces the frozen idx-01/02/03 vectors', () => {
  // Same reasoning as the batch cross-check above: ranges is pure
  // orchestration over indexed generation too (a different way of
  // choosing indices, not a new derivation), so no separate frozen
  // corpus was created for it -- these three existing vectors are the
  // frozen proof for ranges as well as for indexed generation and batch.
  it('ranges [{0,1},{2,2}] matches rsa4096-idx-01/02/03 exactly (0 implicit, 1-2 explicit)', async () => {
    const corpus = loadCorpus();
    const v01 = corpus.rsa4096_indexed_vectors.find((v) => v.id === 'rsa4096-idx-01')!;
    const v02 = corpus.rsa4096_indexed_vectors.find((v) => v.id === 'rsa4096-idx-02')!;
    const v03 = corpus.rsa4096_indexed_vectors.find((v) => v.id === 'rsa4096-idx-03')!;

    // Deliberately request only {1,1} and {2,2} explicitly -- index 0
    // must still appear first via the always-include-0 rule, exactly
    // matching rsa4096-idx-01.
    const results = await generateFromBitStringAtRangesAsync(v01.input_bitstring, [
      { start: 1, end: 1 },
      { start: 2, end: 2 },
    ]);

    expect(results.length).toBe(3);
    expect(results[0]!.address).toBe(v01.address);
    expect(results[1]!.address).toBe(v02.address);
    expect(results[2]!.address).toBe(v03.address);
  }, 60_000);
});
