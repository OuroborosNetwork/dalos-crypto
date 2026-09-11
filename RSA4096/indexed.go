// File indexed.go — deterministic index-based derivation of MULTIPLE
// independent RSA-4096 keypairs (and therefore Arweave addresses) from
// the SAME seed bitstring.
//
// Motivation (settled 2026-09-11): a seed phrase's whole point is to be
// able to derive many usable accounts, not just one -- but RSA has no
// additive-homomorphism trick the way EC scalars do (no "child public
// key = parent public key + offset"), so there is no BIP-32-style
// non-hardened derivation to borrow. Every "child" RSA-4096 key really
// is an independent full keypair, run through the entire prime search
// again -- the derivation only has to produce a fresh, independent,
// deterministic SEED per index; the expensive part (GenerateFromBitString)
// is reused completely unchanged.
//
// Deliberately scoped to the RSA/Arweave layer ONLY. The DALOS/APOLLO EC
// account (Ѻ./Σ./₱./Π.) that produced the input seedBitString is
// untouched by this file -- one Ouronet EC account, many independent
// Arweave addresses under it, not a full parallel HD tree. (A caller who
// wants indexed EC accounts too would derive a different bitstring per
// index at the seed-words layer instead -- a separate, larger change not
// made here.)
//
// Backward compatibility is structural, not just tested: index 0 is
// special-cased to call GenerateFromBitString directly on the
// unmodified seedBitString, so "address #0" is byte-identical, forever,
// to every already-published, already-frozen result -- this file adds
// a capability, it cannot change any existing output.
package RSA4096

import (
	"bytes"
	"encoding/binary"
	"strings"

	"DALOS_Crypto/Blake3"
)

// rsa4096IndexDomainTag is distinct from rsa4096StreamDomainTag
// (stream.go) so index-derivation can never collide with the direct
// seed-to-prime-search stream, even if some index's derived bytes were
// to coincidentally resemble a real seed bitstring.
const rsa4096IndexDomainTag = "DALOS-gen1/RSA4096Index/v1"

// deriveIndexedSeedBitString derives a fresh, independent seed bitstring
// of the SAME length as seedBitString (1024 or 1600 -- whatever
// validateSeedBitString accepts) for a given index. Never called with
// index 0 in practice (GenerateFromBitStringAtIndex short-circuits that
// case) but harmless if it were -- it would simply derive a real,
// different, index-0-flavoured child seed rather than reproducing the
// original, which is exactly why index 0 is special-cased at the call
// site instead of here.
//
// Mechanism: one domain-separated Blake3 hash of (domain tag, the seed
// bitstring's literal ASCII bytes, a 4-byte big-endian index), each
// length-prefixed exactly like stream.go's own NewSeedStream framing,
// asked for exactly len(seedBitString)/8 bytes of output. Rendering
// that output 8 bits per byte, big-endian, produces a bitstring of
// EXACTLY the same length as the input -- so the result automatically
// satisfies allowedSeedBitStringLengths without that gate ever needing
// to know indices exist. (Every length the gate permits -- 1024, 1600
// -- is already an exact multiple of 8, so there is no partial-byte
// case to handle, unlike Elliptic.Ellipse.ConvertHashToBitString which
// also has to cover LETO/ARTEMIS's non-byte-aligned sizes.)
//
// Deliberately NOT chained/sequential: index 1000000's derivation does
// not depend on having derived 1 through 999999 first. Every index is a
// pure function of (seedBitString, index) -- computing index N costs
// exactly one hash, the same as any other index, then the identical
// prime search GenerateFromBitString already runs for index 0. Any
// index is directly reachable; no need to walk forward from 0.
func deriveIndexedSeedBitString(seedBitString string, index uint32) (string, error) {
	if err := validateSeedBitString(seedBitString); err != nil {
		return "", err
	}

	var buf bytes.Buffer
	writeLenPrefixed(&buf, []byte(rsa4096IndexDomainTag))
	writeLenPrefixed(&buf, []byte(seedBitString))
	var indexBytes [4]byte
	binary.BigEndian.PutUint32(indexBytes[:], index)
	writeLenPrefixed(&buf, indexBytes[:])

	// Exact division is safe: allowedSeedBitStringLengths only permits
	// 1024 and 1600, both multiples of 8.
	outputSize := len(seedBitString) / 8
	digest := Blake3.SumCustom(buf.Bytes(), outputSize)

	return hashBytesToBitString(digest), nil
}

// hashBytesToBitString renders b as a big-endian bitstring, 8 characters
// per byte, no leading-zero stripping. Kept local to RSA4096 rather than
// importing Elliptic.Ellipse.ConvertHashToBitString, preserving this
// package's existing zero-dependency-on-Elliptic boundary (see
// stream.go's package doc: "a completely different algebraic structure
// from Gen-1, no elliptic curve").
func hashBytesToBitString(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 8)
	for _, byteVal := range b {
		for bit := 7; bit >= 0; bit-- {
			if (byteVal>>uint(bit))&1 == 1 {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
	}
	return sb.String()
}

// GenerateFromBitStringAtIndex derives Arweave address #index from the
// same seed bitstring that produces address #0 via GenerateFromBitString
// -- the same seed, a multitude of independent addresses, any index
// directly reachable without generating the ones before it.
//
// index == 0 calls GenerateFromBitString directly on the UNMODIFIED
// seedBitString -- byte-identical, forever, to every already-published
// and already-frozen "address #0" result (testvectors/v2_rsa4096.json,
// the live npm package, everything). Every other index runs one extra
// domain-separated hash (deriveIndexedSeedBitString) to derive a fresh,
// independent seed of the same length, then the exact same, otherwise
// completely unmodified, prime-search pipeline index 0 also uses.
func GenerateFromBitStringAtIndex(seedBitString string, index uint32, onProgress ProgressFunc) (*KeyGenResult, error) {
	if index == 0 {
		return GenerateFromBitString(seedBitString, onProgress)
	}
	indexedSeed, err := deriveIndexedSeedBitString(seedBitString, index)
	if err != nil {
		return nil, err
	}
	return GenerateFromBitString(indexedSeed, onProgress)
}
