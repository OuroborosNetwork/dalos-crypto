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

// allowedSeedBitStringLengths is a closed allow-list, not a floor. Earlier
// versions of this package accepted any bitstring >= 128 characters,
// reasoning that Blake3-XOF has no structural opinion on input length --
// true as far as it goes, but it left the door open to an unbounded,
// unaudited "any string, any length" input path with no real derivation
// story and no tie to any validated seed source.
//
// Settled 2026-09-11: RSA-4096's actual security comes from the 2048-bit
// prime search space, not from seed length -- once the seed has enough
// bits to unambiguously seed the Blake3-XOF stream (128 bits already
// cleared that bar many times over), a longer seed buys zero additional
// margin. So there is no reason to accept arbitrary lengths, and a real
// reason not to: gating to EXACTLY the two lengths that come out of this
// repo's two production EC curves -- APOLLO's 1024-bit safe scalar
// (Elliptic/Parameters.go ApolloEllipse().S) and DALOS Genesis's 1600-bit
// safe scalar (DalosEllipse().S) -- structurally forces every RSA seed to
// have passed through one of those two curves' own already-validated
// pipelines (seed-word charset/count checks, bitmap dimensions, etc. --
// see Elliptic/SeedWordsValidation.go), rather than accepting raw bytes
// that never went through any of that.
var allowedSeedBitStringLengths = map[int]bool{
	1024: true, // APOLLO
	1600: true, // DALOS Genesis
}

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

// validateSeedBitString checks that s is exactly one of the allowed
// lengths (see allowedSeedBitStringLengths's doc comment: 1024 for
// APOLLO, 1600 for DALOS Genesis -- no other length, however long, is
// accepted). Mirrors the shape of Elliptic/KeyGeneration.go's
// ValidateBitString but kept local and dependency-free.
func validateSeedBitString(s string) error {
	if !allowedSeedBitStringLengths[len(s)] {
		return errors.New("seed bitstring must be exactly 1024 (APOLLO) or 1600 (DALOS Genesis) characters")
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
// EITHER of the two curves this package accepts (DALOS Genesis's 1600
// bits or APOLLO's 1024 -- see allowedSeedBitStringLengths) -- and
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
