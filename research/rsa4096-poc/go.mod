module dalos-rsa4096-poc

go 1.27.1

// External-validation harness ONLY — not part of the DALOS_Crypto module
// graph. The RSA4096 primitive itself graduated to the real `RSA4096/`
// package at the repo root (2026-09-11); this module now just imports it
// by local path and drives it against real, independent code
// (arweave-core's actual compiled importKeyfile()/addressOf(), and
// Node's native WebCrypto RSA-PSS sign+verify) via validate.mjs /
// validate_golden.mjs. This module is invisible to the root module's
// `go build ./...` / `go vet ./...` / CI gates because it has its own
// go.mod — see main.go's package doc comment.
require DALOS_Crypto v0.0.0

replace DALOS_Crypto => ../../
