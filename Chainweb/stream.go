// Package Chainweb implements deterministic Ed25519 key generation for
// Kadena/Chainweb `k:` accounts from an arbitrary DALOS seed bitstring --
// the "Stoic path": the same seed-words -> DALOS-bitstream pipeline that
// already produces a DALOS Genesis EC identity and (via RSA4096/) an
// Arweave address ALSO produces real, standards-compliant, spendable
// Chainweb accounts, with infinitely many independent positions from one
// seed, none of which can reveal anything about the others or about the
// EC/RSA4096 identities sharing that same root seed.
//
// This mirrors RSA4096/'s own architecture deliberately: a completely
// different algebraic structure from Gen-1 (Ed25519, not DALOS's custom
// Edwards curve), so it does not import Elliptic/ or fit the
// CryptographicPrimitive registry (see docs/ADDING_NEW_PRIMITIVES.md Step
// 8) -- built from scratch on top of Blake3 (seed-expansion XOF, exactly
// like RSA4096/stream.go) plus Go's standard library crypto/ed25519 for
// the actual RFC 8032 key math (unlike RSA4096, which hand-rolls its own
// math/big arithmetic, Ed25519's point arithmetic is exactly the kind of
// thing not worth reimplementing -- crypto/ed25519 is stdlib, so this adds
// zero external dependencies, preserving go.mod's "zero require
// directives" invariant).
//
// See docs/CHAINWEB_STOIC_PATH.md for the full design (once written) and
// the k: address format this produces.
package Chainweb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"DALOS_Crypto/Blake3"
)

// chainwebStreamDomainTag mirrors the domain-tag convention already
// established for Schnorr v2 (Elliptic/Schnorr.go) and RSA4096
// (RSA4096/stream.go: "DALOS-gen1/RSA4096Stream/v1"). A distinct tag from
// both of those means this stream can never collide with, or leak
// anything about, the EC keypair or the RSA4096/Arweave stream that the
// same seed bitstring also produces.
const chainwebStreamDomainTag = "DALOS-gen1/ChainwebEd25519Stream/v1"

// allowedSeedBitStringLengths mirrors RSA4096/stream.go's identical gate,
// for the identical reason: a closed allow-list (not a floor) ties every
// Chainweb seed to one of this repo's two already-validated EC curves'
// own input pipelines (seed-word charset/count checks, etc. -- see
// Elliptic/SeedWordsValidation.go) rather than accepting arbitrary,
// unaudited bytes of any length.
var allowedSeedBitStringLengths = map[int]bool{
	1024: true, // APOLLO
	1600: true, // DALOS Genesis
}

// writeLenPrefixed matches Elliptic/Schnorr.go's and RSA4096/stream.go's
// identical helper: a 4-byte big-endian length prefix followed by the
// data itself, removing any ambiguity about where one concatenated field
// ends and the next begins.
func writeLenPrefixed(buf *bytes.Buffer, data []byte) {
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(data)))
	buf.Write(lenBytes[:])
	buf.Write(data)
}

// validateSeedBitString mirrors RSA4096/stream.go's identical function.
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

// newSeedStream takes a raw seed bitstring (see allowedSeedBitStringLengths)
// plus a position index, and returns an io.Reader producing a fully
// deterministic byte stream, unique to this (seed, index) pair -- exactly
// RSA4096/stream.go's NewSeedStream pattern, with the index folded
// directly into the same hash input rather than requiring a second,
// separate index-derivation hash the way RSA4096/indexed.go does.
//
// RSA4096 needed that two-step dance (deriveIndexedSeedBitString producing
// a FRESH bitstring, then feeding it through the unmodified index-0
// pipeline) specifically to make index 0 byte-identical, forever, to an
// already-published, already-frozen result that existed BEFORE indexing
// was added. This package has no such prior art to preserve -- it is a
// brand-new primitive -- so every index, including 0, can go through one
// uniform formula. Simpler than RSA4096's version, not more complex, and
// there is nothing to special-case.
//
// Only ever needs to produce exactly 32 bytes (Ed25519's seed size) per
// call, unlike RSA4096's stream, which gets read from continuously across
// an entire prime search. Still uses the XOF (not Blake3.SumCustom)
// specifically to reuse the exact same already-audited code path
// RSA4096/stream.go relies on, rather than introducing a second Blake3
// call shape into the codebase for no reason.
func newSeedStream(seedBitString string, index uint32) (io.Reader, error) {
	if err := validateSeedBitString(seedBitString); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writeLenPrefixed(&buf, []byte(chainwebStreamDomainTag))
	writeLenPrefixed(&buf, []byte(seedBitString))
	var indexBytes [4]byte
	binary.BigEndian.PutUint32(indexBytes[:], index)
	writeLenPrefixed(&buf, indexBytes[:])

	h := Blake3.New(0, nil)
	if _, err := h.Write(buf.Bytes()); err != nil {
		// Blake3.Hasher.Write unconditionally returns (len(p), nil) --
		// see RSA4096/stream.go's identical comment, verified by reading
		// Blake3/Blake3.go directly -- so this can never actually happen
		// for an in-memory []byte source; fail fast on principle anyway.
		return nil, err
	}

	return h.XOF(), nil
}
