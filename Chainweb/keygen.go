package Chainweb

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
)

// KeyGenResult is the complete output of one Stoic-path derivation: a real,
// standards-compliant Ed25519 keypair plus the Chainweb `k:` account name
// it corresponds to.
//
// PrivateKey is the 32-byte Ed25519 SEED (RFC 8032), not a manually-clamped
// scalar -- this is the standard "private key" format every real Ed25519
// implementation (libsodium, tweetnacl, Go's own crypto/ed25519, etc.)
// expects to import/export. Signing re-derives the clamped scalar from
// this seed internally; nothing here hand-rolls that step.
//
// Address is fixed by Chainweb/Pact's own protocol convention, not a
// design choice this package makes: exactly "k:" + lowercase-hex(PublicKey).
// Verified directly against real derived accounts (both this repo's own
// Kadena-stoic-legacy Koala/Chainweaver paths and the independent
// third-party KadenaKeys tool) before this package was written.
type KeyGenResult struct {
	Seed       string   // the original DALOS seed bitstring this was derived from
	Index      uint32   // the position (0, 1, 2, ... -- infinitely many independent accounts per seed)
	PrivateKey [32]byte // Ed25519 seed, RFC 8032 -- store/export this as the private key
	PublicKey  [32]byte
	Address    string // "k:" + lowercase-hex(PublicKey) -- a real, spendable Chainweb k: account name
}

// GenerateFromBitString derives Chainweb account #0 (the default/primary
// account) from a DALOS seed bitstring. Equivalent to
// GenerateFromBitStringAtIndex(seedBitString, 0) -- exposed separately
// purely for call-site clarity, mirroring RSA4096's GenerateFromBitString
// / GenerateFromBitStringAtIndex split.
func GenerateFromBitString(seedBitString string) (*KeyGenResult, error) {
	return GenerateFromBitStringAtIndex(seedBitString, 0)
}

// GenerateFromBitStringAtIndex derives Chainweb account #index from the
// same seed bitstring that produces account #0 -- the same seed, a
// multitude of independent accounts, any index directly reachable without
// generating the ones before it (pure function of (seed, index), no
// chained state -- same design principle as RSA4096/indexed.go's
// GenerateFromBitStringAtIndex, which this deliberately parallels).
func GenerateFromBitStringAtIndex(seedBitString string, index uint32) (*KeyGenResult, error) {
	stream, err := newSeedStream(seedBitString, index)
	if err != nil {
		return nil, err
	}

	var seed [32]byte
	if _, err := io.ReadFull(stream, seed[:]); err != nil {
		return nil, fmt.Errorf("Chainweb: failed to read seed material from stream: %w", err)
	}

	priv := ed25519.NewKeyFromSeed(seed[:])
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		// crypto/ed25519.PrivateKey.Public() is documented to always
		// return an ed25519.PublicKey of ed25519.PublicKeySize (32) bytes
		// for any PrivateKey built via NewKeyFromSeed with a
		// SeedSize-length seed (which is guaranteed here: seed is
		// exactly [32]byte, ed25519.SeedSize) -- this can never actually
		// happen; fail fast on principle rather than silently proceeding
		// with a malformed key, per this repo's PO-3 convention.
		return nil, fmt.Errorf("Chainweb: crypto/ed25519 returned an unexpected public key (this should be impossible)")
	}

	var pubArr [32]byte
	copy(pubArr[:], pub)

	return &KeyGenResult{
		Seed:       seedBitString,
		Index:      index,
		PrivateKey: seed,
		PublicKey:  pubArr,
		Address:    "k:" + hex.EncodeToString(pubArr[:]),
	}, nil
}

// SelfCheckEd25519 signs and verifies a fixed test message under the given
// result's keypair, using crypto/ed25519's own Sign/Verify -- an
// independent round-trip proof that the derived key is a genuinely usable
// Ed25519 keypair, not just 64 bytes that happen to look right. Mirrors
// RSA4096's selfCheckTextbookRSA in spirit (see CLAUDE.md invariant #5):
// exported so callers (tests, the test-vector generator, or a consuming
// application) can independently confirm correctness rather than trusting
// generation alone.
func SelfCheckEd25519(r *KeyGenResult) error {
	priv := ed25519.NewKeyFromSeed(r.PrivateKey[:])
	const testMessage = "DALOS_Crypto Chainweb Stoic-path self-check"
	sig := ed25519.Sign(priv, []byte(testMessage))
	if !ed25519.Verify(r.PublicKey[:], []byte(testMessage), sig) {
		return fmt.Errorf("Chainweb: self-check FAILED -- signature did not verify under the derived public key")
	}
	return nil
}
