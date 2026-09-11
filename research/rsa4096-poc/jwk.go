// This file implements the local (zero-network, zero-funds) half of STEP 8:
// encoding the assembled key as a canonical Arweave JWK, and deriving the
// Arweave address from it -- exactly matching the real
// arweave-core/src/keys/{address,keyfile}.ts logic read from
// AncientPantheon/constructors/Codex/packages/arweave-core during this
// session (kty="RSA", e="AQAB", n decodes to exactly 512 bytes, address =
// Base64URL(SHA-256(n))).
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

// arweaveModulusBytes is the canonical 4096-bit modulus length in bytes,
// matching arweave-core's MODULUS_BYTES constant exactly.
const arweaveModulusBytes = 512

// JWK is the canonical 9-field Arweave keyfile shape (mirrors arweave-core's
// ArweaveJwk type exactly: kty + 8 base64url string fields).
type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
	P   string `json:"p"`
	Q   string `json:"q"`
	Dp  string `json:"dp"`
	Dq  string `json:"dq"`
	Qi  string `json:"qi"`
}

// b64url encodes b as unpadded base64url, matching RFC 7518 (JWK) integer
// encoding and arweave-core's expected alphabet.
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// ToJWK encodes k as a canonical Arweave JWK. n is required to be exactly
// arweaveModulusBytes bytes (guaranteed by construction: both p and q have
// their top two bits forced to 1 by GenerateCandidate, so their product
// always has bit-length exactly 4096 -- see the comment in this function for
// the arithmetic proof). Every other field is encoded as its natural
// minimal big-endian byte representation, with no artificial padding --
// identical to how Node/browser WebCrypto export JWKs, and to what
// arweave-core's importKeyfile validates.
func (k *RSAKey) ToJWK() (*JWK, error) {
	nBytes := k.N.Bytes()
	if len(nBytes) != arweaveModulusBytes {
		// Proof this should never happen: p, q each have bit-length exactly
		// 2048 (top two bits forced to 1 by GenerateCandidate), so each lies
		// in [0.75 * 2^2048, 2^2048). Their product n = p*q therefore lies in
		// [0.5625 * 2^4096, 2^4096). Since 0.5625 > 0.5, n's top bit is
		// always 1, so n's bit-length is always exactly 4096 = 512 bytes.
		return nil, errors.New("ToJWK: n is not exactly 512 bytes -- bit-fixing invariant violated upstream")
	}

	return &JWK{
		Kty: "RSA",
		N:   b64url(nBytes),
		E:   b64url(k.E.Bytes()),
		D:   b64url(k.D.Bytes()),
		P:   b64url(k.P.Bytes()),
		Q:   b64url(k.Q.Bytes()),
		Dp:  b64url(k.Dp.Bytes()),
		Dq:  b64url(k.Dq.Bytes()),
		Qi:  b64url(k.Qi.Bytes()),
	}, nil
}

// AddressOf derives the Arweave address Base64URL(SHA-256(n)) directly from
// the modulus, matching arweave-core's addressOf() exactly (verified against
// its actual source this session). Independently re-validates n's decoded
// length itself (does NOT depend on ToJWK having run first, or on any
// particular call order) -- this function has the same "reject a
// wrong-length modulus" guard arweave-core's addressOf() has, self-contained.
func AddressOf(n *big.Int) (string, error) {
	nBytes := n.Bytes()
	if len(nBytes) != arweaveModulusBytes {
		return "", errors.New("AddressOf: n is not exactly 512 bytes")
	}
	digest := sha256.Sum256(nBytes)
	return b64url(digest[:]), nil
}
