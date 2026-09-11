module dalos-rsa4096-poc

go 1.27.1

// Scratch prototype only — not part of the DALOS_Crypto module graph.
// Pulls in the real, audited Blake3 package from the parent repo by
// local path so the prototype tests the actual XOF implementation we'd
// ship with, not a reimplementation. This module is invisible to the
// root module's `go build ./...` / `go vet ./...` / CI gates because it
// has its own go.mod (see research/rsa4096-poc — read the package doc
// comment in stream.go for the plan).
require DALOS_Crypto v0.0.0

replace DALOS_Crypto => ../../
