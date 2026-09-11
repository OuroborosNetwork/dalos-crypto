// Package RSA4096 implements deterministic RSA-4096 key generation from an
// arbitrary DALOS seed bitstring — a real, standards-compliant, fully usable
// RSA-4096 keypair (the format Arweave wallets require), such that the same
// seed always regenerates the exact same keypair, byte-for-byte, forever, on
// any machine. See /.docs/deterministic-rsa4096-from-seed.md for the full
// design history and empirical research (Decision Record §8 and
// Implementation Log §9), and docs/ADDING_NEW_PRIMITIVES.md for how this
// package fits the repo's new-primitive contract.
//
// Graduated from the research/rsa4096-poc/ scratch module, where the design
// was validated against real, independent code: arweave-core's actual
// importKeyfile()/addressOf(), and Node's native WebCrypto RSA-PSS sign and
// verify.
//
// This file implements the seed -> deterministic byte stream stage: turning
// the DALOS 1600-bit seed bitstring into an endless, fully deterministic
// stream of pseudorandom-looking bytes, using the same Blake3 XOF primitive
// already audited and shipped for the EC path (Blake3/Blake3.go,
// ts/src/dalos-blake3).
//
// Nothing here is a cryptographic primitive of its own — Blake3 is already
// the trusted primitive. This is just plumbing: seed in, tap you can read
// forever out.
package RSA4096

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"DALOS_Crypto/Blake3"
)

// rsa4096StreamDomainTag mirrors the domain-tag convention already
// established for Schnorr v2 (Elliptic/Schnorr.go: "DALOS-gen1/SchnorrHash/v1",
// "DALOS-gen1/SchnorrNonce/v1"). Domain separation ensures this stream can
// never collide with any other DALOS construction that also happens to hash
// the same seed bytes for a different purpose.
const rsa4096StreamDomainTag = "DALOS-gen1/RSA4096Stream/v1"

// minSeedBitStringLen is a sanity floor, NOT a cryptographic requirement of
// this construction. Blake3-XOF hashes an input of any length correctly; the
// stream itself has no opinion on how many bits the seed is. This package
// was originally written for the DALOS Genesis 1600-bit seed only, but the
// same pipeline works unchanged for any of DALOS_Crypto's other curve
// safe-scalar sizes -- e.g. APOLLO's 1024 bits (Elliptic/Parameters.go
// ApolloEllipse().S) -- since the seed is just bytes to a hash function, not
// something the RSA construction interprets structurally. 128 bits is
// chosen only to catch obvious mistakes (an empty string, a stray test
// fixture) before they silently become "a weirdly small but 'valid' seed";
// it is comfortably below every real curve this repo defines (LETO's 545 is
// the smallest) and is not itself a security boundary.
const minSeedBitStringLen = 128

// writeLenPrefixed matches Elliptic/Schnorr.go's writeLenPrefixed: a 4-byte
// big-endian length prefix followed by the data itself. This is the same
// Cat-B (v2.0.0) hardening pattern used for the Schnorr transcript — it
// removes any ambiguity about where one field ends and the next begins,
// which matters here because we're concatenating a fixed tag with
// variable-shaped seed material.
func writeLenPrefixed(buf *bytes.Buffer, data []byte) {
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(data)))
	buf.Write(lenBytes[:])
	buf.Write(data)
}

// validateSeedBitString checks that s is at least minSeedBitStringLen
// characters of '0'/'1'. Mirrors the shape of Elliptic/KeyGeneration.go's
// ValidateBitString but kept local and dependency-free, and deliberately
// does NOT pin an exact length -- see minSeedBitStringLen's doc comment.
func validateSeedBitString(s string) error {
	if len(s) < minSeedBitStringLen {
		return errors.New("seed bitstring must be at least 128 characters")
	}
	for _, c := range s {
		if c != '0' && c != '1' {
			return errors.New("seed bitstring must contain only '0' and '1' characters")
		}
	}
	return nil
}

// NewSeedStream takes a raw pre-EC-clamping seed bitstring -- the same
// string GenerateScalarFromBitString consumes before EC-clamping, for
// WHICHEVER curve produced it (DALOS Genesis's 1600 bits, APOLLO's 1024,
// or any other curve's safe-scalar size -- see minSeedBitStringLen) -- and
// returns an io.Reader that produces an effectively endless, fully
// deterministic stream of pseudorandom-looking bytes derived from it.
//
// Design decisions (see Decision Record §8.3 for the full reasoning):
//
//   - Primitive: Blake3 XOF (Blake3.Hasher.XOF()), not a new HMAC_DRBG or
//     SHAKE256 dependency. Already audited and already byte-identical
//     between the Go and TS sides of this repo.
//   - Seed encoding: the bitstring is hashed as its literal ASCII bytes
//     ('0'/'1' characters, 1600 bytes), NOT bit-packed into 200 bytes.
//     This is a deliberate simplicity choice: bit-packing introduces an
//     MSB/LSB ordering decision that is an easy place for the Go and TS
//     implementations to silently disagree. Feeding the literal ASCII
//     bytes is unambiguous, trivial to eyeball/debug, and trivial to
//     reproduce identically in TypeScript (just UTF-8-encode the same
//     string — same bytes, no ordering question exists). The 8x size
//     difference (1600 vs 200 bytes) is irrelevant: this hash runs exactly
//     once per key generation, not in a hot loop.
//   - Framing: domain tag and seed are each length-prefixed before being
//     fed to the hasher (writeLenPrefixed, same convention as
//     Elliptic/Schnorr.go), so there is no ambiguity about where the tag
//     ends and the seed begins.
//   - The hasher is seeded ONCE. Every byte the prime search ever consumes
//     — every candidate's 2048 bits, every Miller-Rabin witness — must come
//     from continuing to Read() this same stream, never from constructing
//     a fresh one. That single continuous stream is what makes the whole
//     pipeline provably tied to the one seed (see the design doc §2's
//     "structural, not statistical" correctness bar).
func NewSeedStream(seedBitString string) (io.Reader, error) {
	if err := validateSeedBitString(seedBitString); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writeLenPrefixed(&buf, []byte(rsa4096StreamDomainTag))
	writeLenPrefixed(&buf, []byte(seedBitString))

	h := Blake3.New(0, nil)
	if _, err := h.Write(buf.Bytes()); err != nil {
		// Blake3.Hasher.Write (Blake3/Blake3.go) unconditionally returns
		// (len(p), nil) -- verified by reading it directly -- so this can
		// never actually happen for an in-memory []byte source; treat any
		// error as a fatal upstream-library regression per the PO-3
		// fail-fast convention already used elsewhere in this repo (see
		// Blake3/Blake3.go:148-150 for the analogous OutputReader.Read
		// panic-on-unexpected-error pattern this mirrors).
		return nil, err
	}

	return h.XOF(), nil
}
