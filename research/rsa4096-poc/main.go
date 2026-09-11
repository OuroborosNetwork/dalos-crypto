// Package main is the EXTERNAL VALIDATION HARNESS for the RSA4096
// primitive, now that it has graduated to the real DALOS_Crypto/RSA4096
// package (see /.docs/deterministic-rsa4096-from-seed.md §9 for the
// research history, and RSA4096/'s own package doc for the production
// package).
//
// This harness is deliberately kept OUTSIDE the root module (its own
// go.mod, invisible to `go build ./...` / CI) because what it does next
// can't run in ordinary CI: it drives the real, compiled
// AncientPantheon/constructors/Codex/packages/arweave-core package (a
// completely separate repo on this machine, at an absolute path) plus
// Node's native WebCrypto, to prove the generated keys are accepted by
// real, independent code -- not just our own implementation agreeing
// with itself.
//
// Reads the frozen corpus (testvectors/v2_rsa4096.json, produced by
// testvectors/generator/main.go and already cross-validated against the
// TypeScript port in ts/tests/rsa4096/), regenerates each vector through
// the real RSA4096 package (a redundant but free sanity check that the
// package still produces what the corpus says), and writes:
//   - jwk.json           (first vector only) for validate.mjs
//   - golden_vectors.json (every vector)      for validate_golden.mjs
//
// Usage:
//
//	cd research/rsa4096-poc
//	go run .                  # regenerates jwk.json + golden_vectors.json
//	node validate.mjs         # cross-checks jwk.json against real arweave-core + WebCrypto
//	node validate_golden.mjs  # same, for every vector in golden_vectors.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	rsa4096 "DALOS_Crypto/RSA4096"
)

// corpusVector mirrors the subset of testvectors/v2_rsa4096.json's fields
// this harness actually needs (the corpus itself has many more -- p, q, d
// in hex, etc. -- already covered by ts/tests/rsa4096's byte-identity
// assertions, so this harness only needs the input to re-derive the rest).
type corpusVector struct {
	ID             string `json:"id"`
	InputBitString string `json:"input_bitstring"`
}

type corpus struct {
	RSA4096Vectors []corpusVector `json:"rsa4096_vectors"`
}

func loadCorpus() []corpusVector {
	data, err := os.ReadFile("../../testvectors/v2_rsa4096.json")
	if err != nil {
		panic(fmt.Sprintf("failed to read testvectors/v2_rsa4096.json: %v", err))
	}
	var c corpus
	if err := json.Unmarshal(data, &c); err != nil {
		panic(fmt.Sprintf("failed to parse testvectors/v2_rsa4096.json: %v", err))
	}
	return c.RSA4096Vectors
}

func writeJSON(path string, v interface{}) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
}

type goldenVector struct {
	SeedName string      `json:"seed_name"`
	Address  string      `json:"address"`
	JWK      *rsa4096.JWK `json:"jwk"`
}

func main() {
	vectors := loadCorpus()
	if len(vectors) == 0 {
		panic("testvectors/v2_rsa4096.json has no rsa4096_vectors")
	}

	var goldenVectors []goldenVector
	for i, v := range vectors {
		fmt.Printf("[%d/%d] %s: regenerating via the real RSA4096 package...\n", i+1, len(vectors), v.ID)
		result, err := rsa4096.GenerateFromBitString(v.InputBitString)
		if err != nil {
			panic(fmt.Sprintf("%s: GenerateFromBitString: %v", v.ID, err))
		}
		if err := rsa4096.SelfCheckTextbookRSA(result.Key); err != nil {
			panic(fmt.Sprintf("%s: SelfCheckTextbookRSA: %v", v.ID, err))
		}
		fmt.Printf("      address=%s\n", result.Address)

		if i == 0 {
			writeJSON("jwk.json", result.JWK)
		}
		goldenVectors = append(goldenVectors, goldenVector{
			SeedName: v.ID,
			Address:  result.Address,
			JWK:      result.JWK,
		})
	}

	writeJSON("golden_vectors.json", goldenVectors)
	fmt.Println("\nwrote jwk.json + golden_vectors.json -- now run:")
	fmt.Println("  node validate.mjs")
	fmt.Println("  node validate_golden.mjs")
}
