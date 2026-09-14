/**
 * Byte-identity test: loads the Go-reference-produced corpus at
 * ../../testvectors/v4_chainweb_ed25519.json and asserts the TypeScript
 * port reproduces every field of every vector exactly, via
 * generateFromBitStringAtIndex -- this is the cross-language correctness
 * assertion the Chainweb/Stoic-path feature exists to satisfy.
 *
 * cw-01/02/03 share ONE seed at indices 0, 1, 2 -- proves indexed
 * generation is genuinely independent per index (see the "no two vectors
 * share an address" check below) and that generateFromBitString equals
 * generateFromBitStringAtIndex(seed, 0).
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  generateFromBitString,
  generateFromBitStringAtIndex,
  selfCheckEd25519,
} from '../../src/chainweb/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const corpusPath = resolve(here, '..', '..', '..', 'testvectors', 'v4_chainweb_ed25519.json');

interface ChainwebVector {
  readonly id: string;
  readonly source: string;
  readonly input_bitstring: string;
  readonly input_words?: readonly string[];
  readonly index: number;
  readonly private_key_hex: string;
  readonly public_key_hex: string;
  readonly address: string;
}

interface ChainwebCorpus {
  readonly schema_version: number;
  readonly chainweb_vectors: readonly ChainwebVector[];
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

const corpus: ChainwebCorpus = JSON.parse(readFileSync(corpusPath, 'utf8'));

describe('Chainweb corpus byte-identity (v4_chainweb_ed25519.json)', () => {
  it('loads a non-empty corpus with the expected vector IDs', () => {
    expect(corpus.chainweb_vectors.length).toBe(6);
    const ids = corpus.chainweb_vectors.map((v) => v.id);
    expect(ids).toEqual(['cw-01', 'cw-02', 'cw-03', 'cw-04', 'cw-05', 'cw-06']);
  });

  for (const vector of corpus.chainweb_vectors) {
    it(`${vector.id}: reproduces private key, public key, and address exactly`, () => {
      const result = generateFromBitStringAtIndex(vector.input_bitstring, vector.index);

      expect(bytesToHex(result.privateKey)).toBe(vector.private_key_hex);
      expect(bytesToHex(result.publicKey)).toBe(vector.public_key_hex);
      expect(result.address).toBe(vector.address);

      // Structural checks on the address format itself, independent of
      // the frozen corpus value -- a real k:<64 lowercase hex> address.
      expect(result.address).toMatch(/^k:[0-9a-f]{64}$/);

      // Every generated key must be a genuinely usable Ed25519 keypair,
      // not just bytes that happen to match the frozen corpus.
      expect(() => selfCheckEd25519(result)).not.toThrow();
    });
  }

  it('cw-01 (index 0) matches plain generateFromBitString for the same seed', () => {
    const cw01 = corpus.chainweb_vectors.find((v) => v.id === 'cw-01');
    if (!cw01) throw new Error('cw-01 vector missing from corpus');

    const plain = generateFromBitString(cw01.input_bitstring);
    expect(bytesToHex(plain.privateKey)).toBe(cw01.private_key_hex);
    expect(plain.address).toBe(cw01.address);
  });

  it('no two vectors share a private key, public key, or address', () => {
    const privateKeys = new Set(corpus.chainweb_vectors.map((v) => v.private_key_hex));
    const publicKeys = new Set(corpus.chainweb_vectors.map((v) => v.public_key_hex));
    const addresses = new Set(corpus.chainweb_vectors.map((v) => v.address));
    expect(privateKeys.size).toBe(corpus.chainweb_vectors.length);
    expect(publicKeys.size).toBe(corpus.chainweb_vectors.length);
    expect(addresses.size).toBe(corpus.chainweb_vectors.length);
  });
});
