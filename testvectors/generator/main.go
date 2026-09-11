// Test vector generator for the DALOS Genesis cryptographic primitive.
//
// Produces a reproducible JSON corpus of input → output pairs covering:
//   - Key generation from fixed-seeded bitstrings
//   - Key generation from seed-word lists (ASCII + Unicode)
//   - Key generation from 40×40 bitmaps (hand-designed + deterministic random)
//   - Schnorr signatures (sign + self-verify; v2.0.0+ uses RFC-6979-style
//     deterministic nonces, so signature bytes are FULLY DETERMINISTIC
//     across runs and across implementations for the same input)
//
// These vectors are the oracle for the forthcoming TypeScript port:
// bit-for-bit equivalence is the correctness criterion.
//
// Usage:
//     cd DALOS_Crypto
//     go run testvectors/generator/main.go
//
// Writes: testvectors/v1_genesis.json
//
// Determinism: math/rand is seeded with fixed constants below. SchnorrSign
// uses RFC-6979-style deterministic nonce derivation (Blake3-tagged KDF
// over the private key + message hash) since v2.0.0, so Schnorr signature
// bytes are FULLY REPRODUCIBLE across runs and across implementations
// (Go ↔ TypeScript port). The 20 Schnorr vectors in v1_genesis.json
// regenerate byte-identically every run.
//
// Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
// See ../LICENSE for terms.

package main

import (
	bmp "DALOS_Crypto/Bitmap"
	el "DALOS_Crypto/Elliptic"
	rsa4096 "DALOS_Crypto/RSA4096"
	"encoding/json"
	"fmt"
	"math/big"
	mrand "math/rand"
	"os"
	"time"
)

// --- Deterministic seeds (fixed forever; changing them invalidates vectors) ---

const (
	RNG_SEED_BITS            int64 = 0xD4105C09702 // "DALOSCRYPTO" in 0x base
	RNG_SEED_BITMAPS         int64 = 0xB17A77      // "BITAPP" in 0x base
	RNG_SEED_BITS_HISTORICAL int64 = 0x415CCEEDED  // "ALICE-CEEDED" — historical bitstring vectors
	RNG_SEED_RSA4096         int64 = 0xC0DE4096    // "CODE4096" in 0x base — dedicated to RSA4096, shares nothing with the EC-path seeds above
)

// --- Vector schema -------------------------------------------------------

type BitStringVector struct {
	ID              string `json:"id"`
	Source          string `json:"source"` // "deterministic-rng"
	InputBitString  string `json:"input_bitstring"`
	ScalarInt10     string `json:"scalar_int10"`
	PrivInt10       string `json:"priv_int10"`
	PrivInt49       string `json:"priv_int49"`
	PublicKey       string `json:"public_key"`
	StandardAddress string `json:"standard_address"`
	SmartAddress    string `json:"smart_address"`
}

type SeedWordsVector struct {
	ID               string   `json:"id"`
	InputWords       []string `json:"input_words"`
	DerivedBitstring string   `json:"derived_bitstring"`
	ScalarInt10      string   `json:"scalar_int10"`
	PrivInt49        string   `json:"priv_int49"`
	PublicKey        string   `json:"public_key"`
	StandardAddress  string   `json:"standard_address"`
	SmartAddress     string   `json:"smart_address"`
}

type BitmapVector struct {
	ID               string   `json:"id"`
	Pattern          string   `json:"pattern"`
	BitmapAscii      []string `json:"bitmap_ascii"` // 40 rows of "#/."; treat as secret
	DerivedBitstring string   `json:"derived_bitstring"`
	ScalarInt10      string   `json:"scalar_int10"`
	PrivInt49        string   `json:"priv_int49"`
	PublicKey        string   `json:"public_key"`
	StandardAddress  string   `json:"standard_address"`
	SmartAddress     string   `json:"smart_address"`
}

type SchnorrVector struct {
	ID             string `json:"id"`
	InputBitString string `json:"input_bitstring"`
	PrivInt49      string `json:"priv_int49"`
	PublicKey      string `json:"public_key"`
	Message        string `json:"message"`
	Signature      string `json:"signature"`       // R-point + s, deterministic per RFC-6979-style nonce derivation (v2.0.0+)
	VerifyExpected bool   `json:"verify_expected"` // always true for our own signatures
	VerifyActual   bool   `json:"verify_actual"`
}

// AdversarialCofactorVector — REQ-19a (T6.7).
//
// Captures a malformed Schnorr signature/public-key whose R or P component
// has been replaced with a point of order ≤ 4 (i.e. lying in the cofactor
// subgroup of the DALOS twisted-Edwards curve, h = 4). A correctly hardened
// SchnorrVerify rejects every such input — the cofactor membership check
// added in T6.2 multiplies R and P by [4] and rejects on identity.
//
// The control vector (adv-control-0001) carries an unmodified, legitimately
// produced signature; verifier MUST accept it. This guards against an
// over-rejection regression where the cofactor check would also discard
// honest signatures.
//
// The construction is permanent regression coverage: any future change that
// silently disables the cofactor check (or, conversely, breaks the legit
// path) will cause the generator's defensive panic to fire.
type AdversarialCofactorVector struct {
	ID                   string `json:"id"`
	Description          string `json:"description"`
	MalformedSignature   string `json:"malformed_signature"`
	LegitMessage         string `json:"legit_message"`
	LegitPublicKey       string `json:"legit_public_key"`
	ExpectedVerifyResult bool   `json:"expected_verify_result"`
	ConstructionMethod   string `json:"construction_method"`
	OrderProof           string `json:"order_proof"`
}

type VectorCorpus struct {
	SchemaVersion    int    `json:"schema_version"`
	GeneratorVersion string `json:"generator_version"`
	Curve            string `json:"curve"`
	CurveFieldPBits  int    `json:"curve_field_p_bits"`
	CurveOrderQBits  int    `json:"curve_order_q_bits"`
	CurveCofactor    string `json:"curve_cofactor"`
	RngSeedBits      string `json:"rng_seed_bits"`
	RngSeedBitmaps   string `json:"rng_seed_bitmaps"`
	GeneratedAtUTC   string `json:"generated_at_utc"`
	Host             string `json:"host"`

	BitStringVectors []BitStringVector `json:"bitstring_vectors"`
	SeedWordsVectors []SeedWordsVector `json:"seed_words_vectors"`
	BitmapVectors    []BitmapVector    `json:"bitmap_vectors"`
	SchnorrVectors   []SchnorrVector   `json:"schnorr_vectors"`
}

// HistoricalSeedWordsVector — like SeedWordsVector but exposes priv_int10 as
// well as priv_int49 so the historical contract tests can cross-check both
// representations of the private key.
type HistoricalSeedWordsVector struct {
	ID               string   `json:"id"`
	InputWords       []string `json:"input_words"`
	DerivedBitString string   `json:"derived_bitstring"`
	ScalarInt10      string   `json:"scalar_int10"`
	PrivInt10        string   `json:"priv_int10"`
	PrivInt49        string   `json:"priv_int49"`
	PublicKey        string   `json:"public_key"`
	StandardAddress  string   `json:"standard_address"`
	SmartAddress     string   `json:"smart_address"`
}

// HistoricalCurveBlock — per-curve container aggregating bitstring,
// seedword, and Schnorr vectors for one historical curve.
type HistoricalCurveBlock struct {
	Curve            string                      `json:"curve"`
	CurveFieldPBits  int                         `json:"curve_field_p_bits"`
	CurveOrderQBits  int                         `json:"curve_order_q_bits"`
	CurveCofactor    string                      `json:"curve_cofactor"`
	BitStringVectors []BitStringVector           `json:"bitstring_vectors"`
	SeedWordsVectors []HistoricalSeedWordsVector `json:"seed_words_vectors"`
	SchnorrVectors   []SchnorrVector             `json:"schnorr_vectors"`
}

// HistoricalVectorCorpus — top-level corpus written to v1_historical.json.
// schema_version 2 distinguishes the historical-curve corpus from the
// schema_version-1 DALOS Genesis corpus.
type HistoricalVectorCorpus struct {
	SchemaVersion    int                  `json:"schema_version"`
	GeneratorVersion string               `json:"generator_version"`
	RngSeedBits      string               `json:"rng_seed_bits"`
	GeneratedAtUTC   string               `json:"generated_at_utc"`
	Host             string               `json:"host"`
	Leto             HistoricalCurveBlock `json:"leto"`
	Artemis          HistoricalCurveBlock `json:"artemis"`
	Apollo           HistoricalCurveBlock `json:"apollo"`
}

// --- Bitstring generation using math/rand (deterministic) ----------------

func randomBitString(rng *mrand.Rand, length int) string {
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		if rng.Intn(2) == 0 {
			buf[i] = '0'
		} else {
			buf[i] = '1'
		}
	}
	return string(buf)
}

// --- Bitmap fixtures -----------------------------------------------------

type bitmapFixture struct {
	name string
	b    bmp.Bitmap
}

func zeroBitmap() bmp.Bitmap { // all white
	return bmp.Bitmap{}
}

func onesBitmap() bmp.Bitmap { // all black
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = true
		}
	}
	return b
}

func checkerboardBitmap() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = (r+c)%2 == 1
		}
	}
	return b
}

func invertedCheckerboard() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = (r+c)%2 == 0
		}
	}
	return b
}

func horizontalStripes() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		black := r%2 == 0
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = black
		}
	}
	return b
}

func verticalStripes() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = c%2 == 0
		}
	}
	return b
}

func border() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			if r == 0 || r == bmp.Rows-1 || c == 0 || c == bmp.Cols-1 {
				b[r][c] = true
			}
		}
	}
	return b
}

func centerCross() bmp.Bitmap {
	var b bmp.Bitmap
	midR := bmp.Rows / 2
	midC := bmp.Cols / 2
	for r := 0; r < bmp.Rows; r++ {
		b[r][midC] = true
	}
	for c := 0; c < bmp.Cols; c++ {
		b[midR][c] = true
	}
	return b
}

func topHalfBlack() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows/2; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = true
		}
	}
	return b
}

func leftHalfBlack() bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols/2; c++ {
			b[r][c] = true
		}
	}
	return b
}

func diagonalTLBR() bmp.Bitmap { // top-left to bottom-right
	var b bmp.Bitmap
	for i := 0; i < bmp.Rows; i++ {
		b[i][i] = true
	}
	return b
}

func diagonalTRBL() bmp.Bitmap { // top-right to bottom-left
	var b bmp.Bitmap
	for i := 0; i < bmp.Rows; i++ {
		b[i][bmp.Cols-1-i] = true
	}
	return b
}

func centerDot() bmp.Bitmap {
	var b bmp.Bitmap
	b[bmp.Rows/2][bmp.Cols/2] = true
	return b
}

func cornersOnly() bmp.Bitmap {
	var b bmp.Bitmap
	b[0][0] = true
	b[0][bmp.Cols-1] = true
	b[bmp.Rows-1][0] = true
	b[bmp.Rows-1][bmp.Cols-1] = true
	return b
}

func quadrantBlack() bmp.Bitmap { // top-left quadrant black, others white
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows/2; r++ {
		for c := 0; c < bmp.Cols/2; c++ {
			b[r][c] = true
		}
	}
	return b
}

func concentricSquares() bmp.Bitmap {
	var b bmp.Bitmap
	// Black on ring 0, 4, 8, 12, 16; white elsewhere.
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			// ring = min distance to the edge
			ring := r
			if bmp.Rows-1-r < ring {
				ring = bmp.Rows - 1 - r
			}
			if c < ring {
				ring = c
			}
			if bmp.Cols-1-c < ring {
				ring = bmp.Cols - 1 - c
			}
			b[r][c] = ring%4 == 0
		}
	}
	return b
}

func randomBitmap(rng *mrand.Rand) bmp.Bitmap {
	var b bmp.Bitmap
	for r := 0; r < bmp.Rows; r++ {
		for c := 0; c < bmp.Cols; c++ {
			b[r][c] = rng.Intn(2) == 1
		}
	}
	return b
}

// --- Seed-word fixtures --------------------------------------------------

var seedWordFixtures = [][]string{
	{"hello", "world", "dalos", "genesis"},
	{"Ouro", "Network", "Testnet"},
	{"a", "b", "c", "d", "e", "f", "g", "h"},
	{"single"},
	{"привет", "мир"},                   // Cyrillic
	{"Γειά", "σου", "κόσμε"},            // Greek
	{"café", "naïve", "façade", "über"}, // Accented Latin
	{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"},
	{"the", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"},
	{"StoaChain", "AncientHoldings", "GmbH"},
	{"Ѻ", "Σ", "DALOS"}, // Account prefix characters themselves
	{"correct", "horse", "battery", "staple"},
	{"Mahatma", "Gandhi", "India", "1947"},
	{"Blake3", "Schnorr", "TwistedEdwards"},
	{"a", "very", "long", "seed", "phrase", "with", "many", "words", "to", "exercise", "the", "hashing"},
}

// --- Historical-corpus fixtures -----------------------------------------
//
// Address prefixes for the historical curves. These are NOT the DALOS
// Genesis prefixes (Ѻ / Σ); each historical curve has its own pair as
// pinned in ts/src/registry/{leto,artemis,apollo}.ts.
var historicalCurvePrefixes = map[string]struct{ Standard, Smart string }{
	"LETO":    {"Ł", "Λ"},
	"ARTEMIS": {"R", "Ř"},
	"APOLLO":  {"₱", "Π"},
}

// historicalSeedWordFixtures — pinned input lists. Five fixtures locks the
// byte-identity contract for the seedword vectors of every historical curve.
var historicalSeedWordFixtures = [][]string{
	{"leto", "artemis", "apollo"},
	{"alpha", "beta", "gamma", "delta"},
	{"genesis", "chronos"},
	{"phi", "chi", "psi", "omega", "sigma"},
	{"crypto", "byte", "identity", "baseline"},
}

// historicalSchnorrMessages — pinned messages for the Schnorr vectors.
var historicalSchnorrMessages = []string{
	"historical-leto-vector-0",
	"historical-artemis-vector-0",
	"historical-apollo-vector-0",
	"shared-message-for-all-curves",
	"test transaction with spaces and 0123456789 digits",
}

// --- Helpers -------------------------------------------------------------

func must(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL [%s]: %v\n", context, err)
		os.Exit(1)
	}
}

// --- Main generator ------------------------------------------------------

func main() {
	generateGenesis()
	generateAdversarial()
	generateHistorical()
	generateRSA4096()
}

func generateGenesis() {
	ellipse := el.DalosEllipse()
	rngBits := mrand.New(mrand.NewSource(RNG_SEED_BITS))
	rngBitmap := mrand.New(mrand.NewSource(RNG_SEED_BITMAPS))

	corpus := VectorCorpus{
		SchemaVersion:    1,
		GeneratorVersion: "3.0.1",
		Curve:            ellipse.Name,
		CurveFieldPBits:  1606,
		CurveOrderQBits:  1604,
		CurveCofactor:    "4",
		RngSeedBits:      fmt.Sprintf("0x%X", RNG_SEED_BITS),
		RngSeedBitmaps:   fmt.Sprintf("0x%X", RNG_SEED_BITMAPS),
		GeneratedAtUTC:   time.Now().UTC().Format(time.RFC3339),
		Host:             "StoaChain/DALOS_Crypto test-vector generator v1.2.0",
	}

	// 1. Bitstring → keys → addresses (50 vectors)
	fmt.Fprintln(os.Stderr, "[1/4] Generating 50 bitstring vectors...")
	for i := 0; i < 50; i++ {
		bits := randomBitString(rngBits, int(ellipse.S))
		scalar, err := ellipse.GenerateScalarFromBitString(bits)
		must(err, fmt.Sprintf("bitstring %d: GenerateScalarFromBitString", i))

		priv, err := ellipse.ScalarToPrivateKey(scalar)
		must(err, fmt.Sprintf("bitstring %d: ScalarToPrivateKey", i))

		keyPair, err := ellipse.ScalarToKeys(scalar)
		must(err, fmt.Sprintf("bitstring %d: ScalarToKeys", i))

		stdAddr := el.DalosAddressMaker(keyPair.PUBL, false)
		smartAddr := el.DalosAddressMaker(keyPair.PUBL, true)

		corpus.BitStringVectors = append(corpus.BitStringVectors, BitStringVector{
			ID:              fmt.Sprintf("bs-%04d", i+1),
			Source:          "deterministic-rng",
			InputBitString:  bits,
			ScalarInt10:     scalar.Text(10),
			PrivInt10:       priv.Int10,
			PrivInt49:       priv.Int49,
			PublicKey:       keyPair.PUBL,
			StandardAddress: stdAddr,
			SmartAddress:    smartAddr,
		})
		if (i+1)%10 == 0 {
			fmt.Fprintf(os.Stderr, "      %d / 50\n", i+1)
		}
	}

	// 2. Seed words → keys → addresses
	fmt.Fprintln(os.Stderr, "[2/4] Generating seed-word vectors...")
	for i, words := range seedWordFixtures {
		bits := ellipse.SeedWordsToBitString(words)
		scalar, err := ellipse.GenerateScalarFromBitString(bits)
		must(err, fmt.Sprintf("seedwords %d: GenerateScalarFromBitString", i))

		priv, err := ellipse.ScalarToPrivateKey(scalar)
		must(err, fmt.Sprintf("seedwords %d: ScalarToPrivateKey", i))

		keyPair, err := ellipse.ScalarToKeys(scalar)
		must(err, fmt.Sprintf("seedwords %d: ScalarToKeys", i))

		corpus.SeedWordsVectors = append(corpus.SeedWordsVectors, SeedWordsVector{
			ID:               fmt.Sprintf("sw-%04d", i+1),
			InputWords:       words,
			DerivedBitstring: bits,
			ScalarInt10:      scalar.Text(10),
			PrivInt49:        priv.Int49,
			PublicKey:        keyPair.PUBL,
			StandardAddress:  el.DalosAddressMaker(keyPair.PUBL, false),
			SmartAddress:     el.DalosAddressMaker(keyPair.PUBL, true),
		})
	}
	fmt.Fprintf(os.Stderr, "      %d fixtures\n", len(seedWordFixtures))

	// 3. Bitmap fixtures → keys → addresses
	fmt.Fprintln(os.Stderr, "[3/4] Generating bitmap vectors...")
	bitmapFixtures := []bitmapFixture{
		{"all-white (zeros)", zeroBitmap()},
		{"all-black (ones)", onesBitmap()},
		{"checkerboard-even", checkerboardBitmap()},
		{"checkerboard-odd", invertedCheckerboard()},
		{"horizontal-stripes", horizontalStripes()},
		{"vertical-stripes", verticalStripes()},
		{"border-frame", border()},
		{"center-cross", centerCross()},
		{"top-half-black", topHalfBlack()},
		{"left-half-black", leftHalfBlack()},
		{"diagonal-tl-br", diagonalTLBR()},
		{"diagonal-tr-bl", diagonalTRBL()},
		{"center-dot", centerDot()},
		{"four-corners", cornersOnly()},
		{"top-left-quadrant", quadrantBlack()},
		{"concentric-squares", concentricSquares()},
		{"random-seed-1", randomBitmap(rngBitmap)},
		{"random-seed-2", randomBitmap(rngBitmap)},
		{"random-seed-3", randomBitmap(rngBitmap)},
		{"random-seed-4", randomBitmap(rngBitmap)},
	}

	for i, fx := range bitmapFixtures {
		keyPair, err := ellipse.GenerateFromBitmap(fx.b)
		must(err, fmt.Sprintf("bitmap %s: GenerateFromBitmap", fx.name))

		bits := bmp.BitmapToBitString(fx.b)
		scalar, err := ellipse.GenerateScalarFromBitString(bits)
		must(err, fmt.Sprintf("bitmap %s: GenerateScalarFromBitString (cross-check)", fx.name))

		priv, err := ellipse.ScalarToPrivateKey(scalar)
		must(err, fmt.Sprintf("bitmap %s: ScalarToPrivateKey", fx.name))

		// Cross-check: bitmap path must produce identical keys to the bitstring
		// path fed the same bits.
		if crossCheck, err2 := ellipse.ScalarToKeys(scalar); err2 == nil {
			if crossCheck.PRIV != keyPair.PRIV || crossCheck.PUBL != keyPair.PUBL {
				fmt.Fprintf(os.Stderr, "FATAL: bitmap %s diverges from bitstring path!\n", fx.name)
				os.Exit(1)
			}
		}

		corpus.BitmapVectors = append(corpus.BitmapVectors, BitmapVector{
			ID:               fmt.Sprintf("bmp-%04d", i+1),
			Pattern:          fx.name,
			BitmapAscii:      bmp.BitmapToAscii(fx.b),
			DerivedBitstring: bits,
			ScalarInt10:      scalar.Text(10),
			PrivInt49:        priv.Int49,
			PublicKey:        keyPair.PUBL,
			StandardAddress:  el.DalosAddressMaker(keyPair.PUBL, false),
			SmartAddress:     el.DalosAddressMaker(keyPair.PUBL, true),
		})
	}
	fmt.Fprintf(os.Stderr, "      %d fixtures (16 hand-designed + 4 deterministic-random)\n", len(bitmapFixtures))

	// 4. Schnorr sign + self-verify (20 vectors)
	fmt.Fprintln(os.Stderr, "[4/4] Generating Schnorr sign+verify vectors...")
	schnorrMessages := []string{
		"",
		"Hello, Ouronet.",
		"The quick brown fox jumps over the lazy dog.",
		"Multi-line\nmessage\nwith\nnewlines",
		"Unicode: αβγδε ҶҸҽӻ 𝔸𝔹ℂ",
		"A" + string(make([]byte, 1024)), // 1 KB
	}
	for i := 0; i < 20; i++ {
		bits := randomBitString(rngBits, int(ellipse.S))
		scalar, err := ellipse.GenerateScalarFromBitString(bits)
		must(err, fmt.Sprintf("schnorr %d: GenerateScalarFromBitString", i))

		priv, err := ellipse.ScalarToPrivateKey(scalar)
		must(err, fmt.Sprintf("schnorr %d: ScalarToPrivateKey", i))

		keyPair, err := ellipse.ScalarToKeys(scalar)
		must(err, fmt.Sprintf("schnorr %d: ScalarToKeys", i))

		msg := schnorrMessages[i%len(schnorrMessages)]
		if i >= len(schnorrMessages) {
			msg = fmt.Sprintf("%s (iteration %d)", msg, i)
		}

		sig, err := ellipse.SchnorrSign(keyPair, msg)
		must(err, fmt.Sprintf("schnorr %d: SchnorrSign", i))
		verifyResult := ellipse.SchnorrVerify(sig, msg, keyPair.PUBL)

		corpus.SchnorrVectors = append(corpus.SchnorrVectors, SchnorrVector{
			ID:             fmt.Sprintf("sch-%04d", i+1),
			InputBitString: bits,
			PrivInt49:      priv.Int49,
			PublicKey:      keyPair.PUBL,
			Message:        msg,
			Signature:      sig,
			VerifyExpected: true,
			VerifyActual:   verifyResult,
		})
	}
	fmt.Fprintf(os.Stderr, "      20 / 20\n")

	// Write corpus atomically: write to .tmp first, then rename so a
	// reader never observes a half-written file.
	tmpPath := "testvectors/v1_genesis.json.tmp"
	finalPath := "testvectors/v1_genesis.json"
	out, err := os.Create(tmpPath)
	must(err, "create output file")

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	err = enc.Encode(corpus)
	must(err, "json encode")
	must(out.Close(), "close output file")
	must(os.Rename(tmpPath, finalPath), "rename v1_genesis.json.tmp")

	// Summary
	totalVectors := len(corpus.BitStringVectors) +
		len(corpus.SeedWordsVectors) +
		len(corpus.BitmapVectors) +
		len(corpus.SchnorrVectors)
	schnorrPass := 0
	for _, v := range corpus.SchnorrVectors {
		if v.VerifyActual {
			schnorrPass++
		}
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "=============================================================")
	fmt.Fprintf(os.Stderr, "  DONE. %d total vectors written to testvectors/v1_genesis.json\n", totalVectors)
	fmt.Fprintf(os.Stderr, "    %d bitstring vectors\n", len(corpus.BitStringVectors))
	fmt.Fprintf(os.Stderr, "    %d seed-words vectors\n", len(corpus.SeedWordsVectors))
	fmt.Fprintf(os.Stderr, "    %d bitmap vectors\n", len(corpus.BitmapVectors))
	fmt.Fprintf(os.Stderr, "    %d schnorr vectors\n", len(corpus.SchnorrVectors))
	fmt.Fprintf(os.Stderr, "    %d / %d schnorr signatures self-verified\n", schnorrPass, len(corpus.SchnorrVectors))
	fmt.Fprintln(os.Stderr, "=============================================================")
}

// generateAdversarial builds the v1_adversarial.json corpus — REQ-19a (T6.7).
//
// Produces 4 attack vectors and 1 control:
//
//   adv-cof-0001 : legit signature with R replaced by the order-2 point
//                  (0, P-1). [4]·(0, P-1) = O, so the cofactor check in
//                  SchnorrVerify (T6.2) rejects it.
//   adv-cof-0002 : legit signature, but the public key is replaced with
//                  the canonical wire-format encoding of (0, P-1).
//   adv-cof-0003 : both R and the public key replaced with (0, P-1).
//   adv-edge-0001: legit signature with R replaced by the curve identity
//                  (0, 1). [4]·O = O — the cofactor check catches it
//                  (in addition to the on-curve identity guard).
//   adv-control  : a legitimate signature, untouched. MUST verify true,
//                  proving the cofactor check does not over-reject.
//
// The order-2 point (0, P-1) is on the twisted-Edwards curve a·x² + y² =
// 1 + d·x²·y² for any (a, d): with x = 0 and y = -1 (mod P), the equation
// becomes 0 + 1 = 1 + 0, which holds. Doubling it on the curve yields the
// identity (0, 1), confirming order 2 — hence membership in the cofactor-4
// subgroup.
//
// After generating all 5 vectors the function asserts 4 rejections and
// 1 acceptance. Failure to meet that ratio panics — that is the explicit
// signal that the cofactor membership check has silently regressed.
func generateAdversarial() {
	ellipse := el.DalosEllipse()

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "=============================================================")
	fmt.Fprintln(os.Stderr, "  Generating adversarial cofactor vectors (REQ-19a / T6.7)...")

	// Dedicated RNG seed so the existing 105-vector streams stay byte-identical.
	rngAdv := mrand.New(mrand.NewSource(0xADCFAC704))

	bits := randomBitString(rngAdv, int(ellipse.S))
	scalar, err := ellipse.GenerateScalarFromBitString(bits)
	must(err, "adversarial: GenerateScalarFromBitString")
	keyPair, err := ellipse.ScalarToKeys(scalar)
	must(err, "adversarial: ScalarToKeys")

	legitMsg := "T6.7-cofactor-adversarial-vector"
	legitSig, err := ellipse.SchnorrSign(keyPair, legitMsg)
	must(err, "adversarial: SchnorrSign(legit)")
	if !ellipse.SchnorrVerify(legitSig, legitMsg, keyPair.PUBL) {
		panic("adversarial generator: legit signature failed self-verify (cannot proceed)")
	}

	// The order-2 point T₂ = (0, P-1). Its affine wire-format encoding is
	// the malicious public key for adv-cof-0002 / adv-cof-0003.
	pMinusOne := new(big.Int).Sub(&ellipse.P, big.NewInt(1))
	t2Affine := el.CoordAffine{AX: new(big.Int).SetInt64(0), AY: new(big.Int).Set(pMinusOne)}
	maliciousPubKey := el.AffineToPublicKey(t2Affine)

	// The curve identity (0, 1) for adv-edge-0001.
	identityAffine := el.CoordAffine{AX: new(big.Int).SetInt64(0), AY: new(big.Int).SetInt64(1)}

	// Helper: clone the legit signature and swap its R for the supplied affine.
	mutateR := func(newR el.CoordAffine) string {
		parsed, perr := el.ConvertSchnorrSignatureAsStringToStructure(legitSig)
		if perr != nil {
			panic(fmt.Sprintf("adversarial generator: parse legit sig: %v", perr))
		}
		parsed.R = newR
		return el.ConvertSchnorrSignatureToString(parsed)
	}

	type adversarialCase struct {
		id              string
		description     string
		signature       string
		publicKey       string
		expectAccept    bool
		construction    string
		orderProof      string
	}

	cases := []adversarialCase{
		{
			id:           "adv-cof-0001",
			description:  "Legit signature with R replaced by the order-2 point (0, P-1).",
			signature:    mutateR(t2Affine),
			publicKey:    keyPair.PUBL,
			expectAccept: false,
			construction: "R := CoordAffine{AX: 0, AY: P-1}; re-serialize via ConvertSchnorrSignatureToString.",
			orderProof:   "On twisted-Edwards a·x²+y² = 1+d·x²·y², (0,-1) gives 0+1 = 1+0 ✓; doubling yields identity (0,1) → order 2 → lies in the cofactor-4 subgroup → [4]·R = O.",
		},
		{
			id:           "adv-cof-0002",
			description:  "Legit signature, public key replaced with the order-2 point (0, P-1) in canonical wire format.",
			signature:    legitSig,
			publicKey:    maliciousPubKey,
			expectAccept: false,
			construction: "publicKey := AffineToPublicKey(CoordAffine{AX: 0, AY: P-1}).",
			orderProof:   "Same as adv-cof-0001 — (0, P-1) has order 2 and lies in the 4-torsion subgroup; [4]·P = O.",
		},
		{
			id:           "adv-cof-0003",
			description:  "Legit signature with both R AND public key replaced by (0, P-1).",
			signature:    mutateR(t2Affine),
			publicKey:    maliciousPubKey,
			expectAccept: false,
			construction: "Combine adv-cof-0001 (R swap) with adv-cof-0002 (public-key swap).",
			orderProof:   "Both R and P are the order-2 point (0, P-1); [4]·R = [4]·P = O.",
		},
		{
			id:           "adv-edge-0001",
			description:  "Legit signature with R replaced by the curve identity (0, 1).",
			signature:    mutateR(identityAffine),
			publicKey:    keyPair.PUBL,
			expectAccept: false,
			construction: "R := CoordAffine{AX: 0, AY: 1} — affine encoding of the extended-coords identity {0,1,1,0}.",
			orderProof:   "Identity has order 1; trivially [4]·O = O. Cofactor check rejects.",
		},
		{
			id:           "adv-control-0001",
			description:  "Untouched legit signature. Verifier MUST accept; proves cofactor check does not over-reject honest inputs.",
			signature:    legitSig,
			publicKey:    keyPair.PUBL,
			expectAccept: true,
			construction: "Direct output of SchnorrSign(keyPair, legitMsg) — no mutation.",
			orderProof:   "n/a (control). Honest R = [z]·G with z ∈ [1, Q-1] satisfies [4]·R ≠ O because gcd(4, Q) = 1.",
		},
	}

	adversarialVectors := make([]AdversarialCofactorVector, 0, len(cases))
	adversarialReject := 0
	controlAccept := 0
	for _, c := range cases {
		actual := ellipse.SchnorrVerify(c.signature, legitMsg, c.publicKey)
		if c.expectAccept {
			if actual {
				controlAccept++
			}
		} else {
			if !actual {
				adversarialReject++
			}
		}

		adversarialVectors = append(adversarialVectors, AdversarialCofactorVector{
			ID:                   c.id,
			Description:          c.description,
			MalformedSignature:   c.signature,
			LegitMessage:         legitMsg,
			LegitPublicKey:       c.publicKey,
			ExpectedVerifyResult: c.expectAccept,
			ConstructionMethod:   c.construction,
			OrderProof:           c.orderProof,
		})
	}

	// Defensive panic — fires if the cofactor check is silently inactive
	// (no rejections) or if it has over-rejected the control (no acceptance).
	// This is the load-bearing assertion for T6.7 / REQ-19a.
	if adversarialReject != 4 || controlAccept != 1 {
		panic(fmt.Sprintf(
			"cofactor-check inactive or over-rejecting: %d/4 attacks rejected, %d/1 controls accepted",
			adversarialReject, controlAccept))
	}

	// Write atomically: .tmp then rename, so concurrent readers never observe
	// a half-written file. Same pattern as the genesis/historical writers.
	//
	// F-LOW-013 (audit cycle 2026-05-04, v4.0.3): added schema_version
	// field — both genesis (schema_version=1) and historical (schema_
	// version=2) corpora declare a top-level version, and their TS
	// loaders (`ts/tests/fixtures.ts`) validate the field BEFORE caching.
	// Adversarial was the odd-one-out: no version, no loader gate. Now
	// declared at version 1 (initial). Future schema changes (e.g.,
	// adding new attack-vector classes) bump the number; the TS loader's
	// matching gate refuses to load mismatched-version files, defending
	// against silent stale-corpus consumption.
	adversarialOutput := struct {
		SchemaVersion              int                          `json:"schema_version"`
		AdversarialCofactorVectors []AdversarialCofactorVector `json:"adversarial_cofactor_vectors"`
	}{
		SchemaVersion:              1,
		AdversarialCofactorVectors: adversarialVectors,
	}
	adversarialJSON, err := json.MarshalIndent(adversarialOutput, "", "  ")
	must(err, "marshal adversarial corpus")

	tmpPath := "testvectors/v1_adversarial.json.tmp"
	finalPath := "testvectors/v1_adversarial.json"
	must(os.WriteFile(tmpPath, adversarialJSON, 0644), "write v1_adversarial.json.tmp")
	must(os.Rename(tmpPath, finalPath), "rename v1_adversarial.json.tmp")

	fmt.Fprintf(os.Stderr, "  %d / 4 adversarial signatures correctly REJECTED by SchnorrVerify\n", adversarialReject)
	fmt.Fprintf(os.Stderr, "  %d / 1 control signatures correctly ACCEPTED by SchnorrVerify\n", controlAccept)
	fmt.Fprintf(os.Stderr, "  DONE. 5 adversarial vectors written to %s\n", finalPath)
	fmt.Fprintln(os.Stderr, "=============================================================")
}

// generateHistorical builds the v1_historical.json corpus covering the
// LETO, ARTEMIS, and APOLLO twisted-Edwards curves. Each curve gets:
//   - 10 bitstring vectors driven by RNG_SEED_BITS_HISTORICAL
//   - 5 seed-word vectors from historicalSeedWordFixtures
//   - 5 Schnorr sign+verify vectors over historicalSchnorrMessages
//
// Address prefixes are per-curve (NOT the DALOS Genesis Ѻ/Σ prefixes).
func generateHistorical() {
	rngHistorical := mrand.New(mrand.NewSource(RNG_SEED_BITS_HISTORICAL))

	curves := []struct {
		name    string
		factory func() el.Ellipse
	}{
		{"LETO", el.LetoEllipse},
		{"ARTEMIS", el.ArtemisEllipse},
		{"APOLLO", el.ApolloEllipse},
	}

	corpus := HistoricalVectorCorpus{
		SchemaVersion:    2,
		GeneratorVersion: "3.0.1",
		RngSeedBits:      fmt.Sprintf("0x%X", RNG_SEED_BITS_HISTORICAL),
		GeneratedAtUTC:   time.Now().UTC().Format(time.RFC3339),
		Host:             "StoaChain/DALOS_Crypto test-vector generator v3.0.1",
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "=============================================================")
	fmt.Fprintln(os.Stderr, "  Generating historical corpus (LETO + ARTEMIS + APOLLO)...")

	for _, c := range curves {
		ellipse := c.factory()
		prefixes := historicalCurvePrefixes[c.name]
		block := HistoricalCurveBlock{
			Curve:           c.name,
			CurveFieldPBits: ellipse.P.BitLen(),
			CurveOrderQBits: ellipse.Q.BitLen(),
			CurveCofactor:   "4",
		}

		// 10 bitstring vectors.
		for i := 0; i < 10; i++ {
			bits := randomBitString(rngHistorical, int(ellipse.S))
			scalar, err := ellipse.GenerateScalarFromBitString(bits)
			must(err, fmt.Sprintf("%s bitstring %d: GenerateScalarFromBitString", c.name, i))

			priv, err := ellipse.ScalarToPrivateKey(scalar)
			must(err, fmt.Sprintf("%s bitstring %d: ScalarToPrivateKey", c.name, i))

			kp, err := ellipse.ScalarToKeys(scalar)
			must(err, fmt.Sprintf("%s bitstring %d: ScalarToKeys", c.name, i))

			body := el.PublicKeyToAddress(kp.PUBL)
			block.BitStringVectors = append(block.BitStringVectors, BitStringVector{
				ID:              fmt.Sprintf("%s-bs-%02d", c.name, i),
				Source:          "deterministic-rng",
				InputBitString:  bits,
				ScalarInt10:     scalar.Text(10),
				PrivInt10:       priv.Int10,
				PrivInt49:       priv.Int49,
				PublicKey:       kp.PUBL,
				StandardAddress: prefixes.Standard + "." + body,
				SmartAddress:    prefixes.Smart + "." + body,
			})
		}

		// 5 seedword vectors.
		for i, words := range historicalSeedWordFixtures {
			bits := ellipse.SeedWordsToBitString(words)
			scalar, err := ellipse.GenerateScalarFromBitString(bits)
			must(err, fmt.Sprintf("%s seedwords %d: GenerateScalarFromBitString", c.name, i))

			priv, err := ellipse.ScalarToPrivateKey(scalar)
			must(err, fmt.Sprintf("%s seedwords %d: ScalarToPrivateKey", c.name, i))

			kp, err := ellipse.ScalarToKeys(scalar)
			must(err, fmt.Sprintf("%s seedwords %d: ScalarToKeys", c.name, i))

			body := el.PublicKeyToAddress(kp.PUBL)
			block.SeedWordsVectors = append(block.SeedWordsVectors, HistoricalSeedWordsVector{
				ID:               fmt.Sprintf("%s-sw-%02d", c.name, i),
				InputWords:       words,
				DerivedBitString: bits,
				ScalarInt10:      scalar.Text(10),
				PrivInt10:        priv.Int10,
				PrivInt49:        priv.Int49,
				PublicKey:        kp.PUBL,
				StandardAddress:  prefixes.Standard + "." + body,
				SmartAddress:     prefixes.Smart + "." + body,
			})
		}

		// 5 Schnorr vectors.
		for i, msg := range historicalSchnorrMessages {
			bits := randomBitString(rngHistorical, int(ellipse.S))
			scalar, err := ellipse.GenerateScalarFromBitString(bits)
			must(err, fmt.Sprintf("%s schnorr %d: GenerateScalarFromBitString", c.name, i))

			priv, err := ellipse.ScalarToPrivateKey(scalar)
			must(err, fmt.Sprintf("%s schnorr %d: ScalarToPrivateKey", c.name, i))

			kp, err := ellipse.ScalarToKeys(scalar)
			must(err, fmt.Sprintf("%s schnorr %d: ScalarToKeys", c.name, i))

			sig, err := ellipse.SchnorrSign(kp, msg)
			must(err, fmt.Sprintf("%s schnorr %d: SchnorrSign", c.name, i))
			verifyResult := ellipse.SchnorrVerify(sig, msg, kp.PUBL)

			block.SchnorrVectors = append(block.SchnorrVectors, SchnorrVector{
				ID:             fmt.Sprintf("%s-sch-%02d", c.name, i),
				InputBitString: bits,
				PrivInt49:      priv.Int49,
				PublicKey:      kp.PUBL,
				Message:        msg,
				Signature:      sig,
				VerifyExpected: true,
				VerifyActual:   verifyResult,
			})
		}

		switch c.name {
		case "LETO":
			corpus.Leto = block
		case "ARTEMIS":
			corpus.Artemis = block
		case "APOLLO":
			corpus.Apollo = block
		}

		fmt.Fprintf(os.Stderr, "    %s: %d bitstring + %d seedwords + %d schnorr\n",
			c.name,
			len(block.BitStringVectors),
			len(block.SeedWordsVectors),
			len(block.SchnorrVectors))
	}

	tmpPath := "testvectors/v1_historical.json.tmp"
	finalPath := "testvectors/v1_historical.json"
	out, err := os.Create(tmpPath)
	must(err, "create v1_historical.json.tmp")

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	must(enc.Encode(corpus), "encode historical corpus")
	must(out.Close(), "close v1_historical.json.tmp")
	must(os.Rename(tmpPath, finalPath), "rename v1_historical.json.tmp")

	totalVectors :=
		len(corpus.Leto.BitStringVectors) + len(corpus.Leto.SeedWordsVectors) + len(corpus.Leto.SchnorrVectors) +
			len(corpus.Artemis.BitStringVectors) + len(corpus.Artemis.SeedWordsVectors) + len(corpus.Artemis.SchnorrVectors) +
			len(corpus.Apollo.BitStringVectors) + len(corpus.Apollo.SeedWordsVectors) + len(corpus.Apollo.SchnorrVectors)

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "  DONE. %d historical vectors written to %s\n", totalVectors, finalPath)
	fmt.Fprintln(os.Stderr, "=============================================================")
}

// --- RSA4096 corpus --------------------------------------------------------
//
// RSA4096Vector captures one full seed -> RSA-4096 JWK derivation. Unlike
// the EC vectors above, this corpus's JWK field is the exact struct type
// the RSA4096 package itself produces (RSA4096.JWK) -- reusing the real
// type instead of a copy keeps the corpus schema and the package's actual
// output shape mechanically in sync; they cannot drift apart by accident.
type RSA4096Vector struct {
	ID              string      `json:"id"`
	Source          string      `json:"source"` // "deterministic-rng" or "seed-words"
	InputBitString  string      `json:"input_bitstring"`
	InputWords      []string    `json:"input_words,omitempty"`
	PrimeP          string      `json:"prime_p_hex"`
	PrimeQ          string      `json:"prime_q_hex"`
	ModulusN        string      `json:"modulus_n_hex"`
	PrivateExponent string      `json:"private_exponent_d_hex"`
	Dp              string      `json:"dp_hex"`
	Dq              string      `json:"dq_hex"`
	Qi              string      `json:"qi_hex"`
	JWK             rsa4096.JWK `json:"jwk"`
	Address         string      `json:"address"`
	PAttempts       int         `json:"p_attempts"`
	QAttempts       int         `json:"q_attempts"`
}

// RSA4096Corpus -- top-level corpus written to v2_rsa4096.json. schema_version
// 1 (independent of the EC corpora's own version numbers, since this is a
// wholly separate primitive per docs/ADDING_NEW_PRIMITIVES.md's naming rule).
type RSA4096Corpus struct {
	SchemaVersion     int             `json:"schema_version"`
	GeneratorVersion  string          `json:"generator_version"`
	RngSeedBits       string          `json:"rng_seed_bits"`
	MillerRabinRounds int             `json:"miller_rabin_rounds"`
	SmallPrimeCount   int             `json:"small_prime_count"`
	GeneratedAtUTC    string          `json:"generated_at_utc"`
	Host              string          `json:"host"`
	Vectors           []RSA4096Vector `json:"rsa4096_vectors"`
}

// generateRSA4096 builds the v2_rsa4096.json corpus: two RNG-driven 1600-bit
// seeds plus one real DALOS seed-word fixture (the same seedWordFixtures[0]
// used by the EC bitstring-vs-seedwords vectors above), each run through
// the full RSA4096.GenerateFromBitString pipeline.
//
// Deliberately few vectors (3): each full generation costs low-single-digit
// seconds (finding two 2048-bit primes from scratch), so this corpus trades
// vector count for keeping `go run testvectors/generator/main.go` -- which
// CI re-runs on every push touching Go code -- fast. Three is enough to
// exercise both seed-input paths (bitstring + seed-words) and catch any
// regression in the deterministic pipeline; it is not trying to be a
// statistical sample the way the 50-vector EC bitstring corpus is.
func generateRSA4096() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "=============================================================")
	fmt.Fprintln(os.Stderr, "  Generating RSA4096 corpus (deterministic seed -> Arweave JWK)...")

	ellipse := el.DalosEllipse()
	rngRSA := mrand.New(mrand.NewSource(RNG_SEED_RSA4096))

	corpus := RSA4096Corpus{
		SchemaVersion:     1,
		GeneratorVersion:  "1.0.0",
		RngSeedBits:       fmt.Sprintf("0x%X", RNG_SEED_RSA4096),
		MillerRabinRounds: rsa4096.MillerRabinRounds,
		SmallPrimeCount:   rsa4096.SmallPrimeCount,
		GeneratedAtUTC:    time.Now().UTC().Format(time.RFC3339),
		Host:              "StoaChain/DALOS_Crypto test-vector generator (RSA4096 v1.0.0)",
	}

	addVector := func(id, source, bits string, words []string) {
		result, err := rsa4096.GenerateFromBitString(bits, nil)
		must(err, fmt.Sprintf("rsa4096 %s: GenerateFromBitString", id))

		if result.Key.N.BitLen() != 4096 {
			panic(fmt.Sprintf("rsa4096 %s: n is %d bits, want 4096", id, result.Key.N.BitLen()))
		}
		if len(result.Address) != 43 {
			panic(fmt.Sprintf("rsa4096 %s: address is %d chars, want 43", id, len(result.Address)))
		}
		must(rsa4096.SelfCheckTextbookRSA(result.Key), fmt.Sprintf("rsa4096 %s: SelfCheckTextbookRSA", id))

		corpus.Vectors = append(corpus.Vectors, RSA4096Vector{
			ID:              id,
			Source:          source,
			InputBitString:  bits,
			InputWords:      words,
			PrimeP:          result.P.Text(16),
			PrimeQ:          result.Q.Text(16),
			ModulusN:        result.Key.N.Text(16),
			PrivateExponent: result.Key.D.Text(16),
			Dp:              result.Key.Dp.Text(16),
			Dq:              result.Key.Dq.Text(16),
			Qi:              result.Key.Qi.Text(16),
			JWK:             *result.JWK,
			Address:         result.Address,
			PAttempts:       result.PAttempts,
			QAttempts:       result.QAttempts,
		})
		fmt.Fprintf(os.Stderr, "    %s: address=%s (p_attempts=%d, q_attempts=%d)\n", id, result.Address, result.PAttempts, result.QAttempts)
	}

	addVector("rsa4096-bs-01", "deterministic-rng", randomBitString(rngRSA, int(ellipse.S)), nil)
	addVector("rsa4096-bs-02", "deterministic-rng", randomBitString(rngRSA, int(ellipse.S)), nil)
	addVector("rsa4096-sw-01", "seed-words", ellipse.SeedWordsToBitString(seedWordFixtures[0]), seedWordFixtures[0])

	tmpPath := "testvectors/v2_rsa4096.json.tmp"
	finalPath := "testvectors/v2_rsa4096.json"
	out, err := os.Create(tmpPath)
	must(err, "create v2_rsa4096.json.tmp")

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	must(enc.Encode(corpus), "encode RSA4096 corpus")
	must(out.Close(), "close v2_rsa4096.json.tmp")
	must(os.Rename(tmpPath, finalPath), "rename v2_rsa4096.json.tmp")

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "  DONE. %d RSA4096 vectors written to %s\n", len(corpus.Vectors), finalPath)
	fmt.Fprintln(os.Stderr, "=============================================================")
}
