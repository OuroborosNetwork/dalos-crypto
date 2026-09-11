package Elliptic

import (
    "DALOS_Crypto/Bitmap"
    "DALOS_Crypto/Blake3"
    aux "DALOS_Crypto/Auxilliary"
    "crypto/rand"
    "errors"
    "fmt"
    "math/big"
    "strings"
)

type DalosKeyPair struct {
    PRIV string
    PUBL string
}

type DalosPrivateKey struct {
    BitString string
    Int10     string
    Int49     string
}

// Phase 10 (REQ-31, v4.0.0): PrintKeys + PrintPrivateKey moved to
// `print.go` at repo root (package main). This file retains pure-crypto
// only — see ../keystore/ for wallet I/O and ../process.go for CLI
// orchestration.

func DalosAddressMaker(PublicKey string, SmartOrStandard bool) string {
    //Creates either a Standard Dalos Account Address or a Smart Dalor Account Address
    Matrix := CharacterMatrix()
    Standard := string(Matrix[0][10]) // Get the rune at [0][10]
    Smart := string(Matrix[11][9])    // Get the rune at [11][9]
    Address := PublicKeyToAddress(PublicKey)
    
    if SmartOrStandard {
        return Smart + "." + Address
    } else {
        return Standard + "." + Address
    }
}

// PublicKeyToAddress derives a 160-character DALOS account address from a
// public key in canonical "{xLength-base49}.{body-base49}" string form.
//
// HARDENING (v4.0.1, audit cycle 2026-05-04, F-ERR-003): the pre-v4.0.1
// implementation had two latent crash/silent-corruption vectors:
//
//   1. `SplitString[1]` with no length check → index-out-of-range panic
//      on any input lacking the dot separator.
//   2. `(*big.Int).SetString(_, 49)` with the `ok` return discarded →
//      malformed base-49 input (e.g., a truncated wallet PUBL field, a
//      misplaced separator) silently produced an undefined big.Int that
//      flowed through the seven-fold Blake3 chain into a "valid-looking"
//      160-character address bearing no relation to any real key.
//
// Post-v4.0.1 contract: panic on malformed input (matches the FP-001 /
// PO-3 / KG-3 fail-fast convention — a corrupted PUBL is an
// internal-consistency violation, not a recoverable user-input error,
// and silently returning garbage from an address-deriving function is
// strictly worse than crashing loudly). The TS port's
// `publicKeyToAddress` (`ts/src/gen1/hashing.ts:255-266`) throws on the
// same conditions; this brings Go ↔ TS parity.
func PublicKeyToAddress(PublicKey string) string {
    //From the PublicKey string, the Prefix is removed in order to obtain the PublicKeyInt
    //as in integer in Base49
    SplitString := strings.Split(PublicKey, ".")
    if len(SplitString) != 2 {
        panic(fmt.Sprintf("PublicKeyToAddress: malformed public key (expected exactly 1 \".\", got %d): %q", len(SplitString)-1, PublicKey))
    }
    PublicKeyIntStr := SplitString[1] //Public Key as a Number in Base 49 in the form of a string

    PublicKeyIntDecimal, err := ConvertBase49toBase10(PublicKeyIntStr)
    if err != nil {
        panic(fmt.Sprintf("PublicKeyToAddress: malformed base-49 body: %v", err))
    }
    Address := DalosAddressComputer(PublicKeyIntDecimal)
    return Address
}

func DalosAddressComputer(PublicKeyInt *big.Int) string {
    PublicKeyIntAsString := PublicKeyInt.String()
    Hash0 := []byte(PublicKeyIntAsString)
    
    //Seven Fold Hash
    Hash1 := Blake3.SumCustom(Hash0, 160)
    Hash2 := Blake3.SumCustom(Hash1, 160)
    Hash3 := Blake3.SumCustom(Hash2, 160)
    Hash4 := Blake3.SumCustom(Hash3, 160)
    Hash5 := Blake3.SumCustom(Hash4, 160)
    Hash6 := Blake3.SumCustom(Hash5, 160)
    Hash7 := Blake3.SumCustom(Hash6, 160)
    
    //Converting To Letters
    Account := ConvertToLetters(Hash7)
    return Account
}

// ConvertToLetters maps each byte of `hash` to a Unicode rune via the
// 16×16 CharacterMatrix and returns the resulting string. Used by the
// Demiourgos address derivation (see DalosAddressComputer above).
//
// HARDENING (v4.0.3, audit cycle 2026-05-04, F-LOW-005): the pre-v4.0.3
// implementation built the result via repeated `[]string` append +
// final `strings.Join`. Each iteration allocated TWO heap strings: the
// single-rune `string(Matrix[row][col])` conversion AND the slice
// re-grow when `append` ran out of capacity. For a typical 160-byte
// `hash` input (the post-seven-fold-Blake3 buffer in
// `DalosAddressComputer`), that's 160 single-char string allocs +
// log₂(160) ≈ 8 slice re-grows = ~168 heap allocations + ~10–50 µs of
// pure GC pressure per address derivation.
//
// Post-v4.0.3: `strings.Builder.Grow + WriteRune`. Single buffer pre-
// sized to the upper bound (4 bytes per rune × len(hash), since
// CharacterMatrix runes can be up to U+FFFF and UTF-8-encode to 1-3
// bytes; the 4× upper bound is conservative and avoids any re-grow).
// One allocation at Grow, one at .String(). Matches the established
// in-file template at `GenerateRandomBitsOnCurve` (lines 168 area).
//
// Output is byte-identical: same sequence of runes, same order, same
// UTF-8 encoding. Genesis byte-identity preserved (verified via the
// 105-vector corpus byte-identity gate; ConvertToLetters is on every
// `Ѻ.` / `Σ.` address-derivation path the corpus exercises).
func ConvertToLetters(hash []byte) string {
    Matrix := CharacterMatrix()
    var b strings.Builder
    // Pre-size: 4 bytes-per-rune × len(hash) is the conservative upper
    // bound (UTF-8 encodes any code point in the BMP in ≤3 bytes; 4 is
    // future-proof if the matrix ever gains supplementary-plane code
    // points). Eliminates buffer re-grows on the typical 160-byte input.
    b.Grow(len(hash) * 4)
    for _, value := range hash {
        // Calculate row and column index for the Matrix
        row := value / 16 // Each row has 16 elements
        col := value % 16 // Column index within the row
        b.WriteRune(Matrix[row][col])
    }
    return b.String()
}

// AffineToPublicKey serialises a CoordAffine point to the canonical
// "{xLength-base49}.{xy-base49}" public-key string format.
//
// HARDENING (v4.0.1, audit cycle 2026-05-04, F-ERR-003): added explicit
// nil-checks on Input.AX and Input.AY at function entry. Pre-v4.0.1, a
// zero-value CoordAffine (uninitialised struct, or one reaching this
// function from a buggy caller) would panic obscurely on the first
// `.String()` call with a generic "runtime error: invalid memory
// address or nil pointer dereference". The new explicit panic names
// the function and offending field so the failure mode is debuggable.
//
// The `_ = ok` from `SetString(XYString, 10)` is preserved as
// defense-in-depth: XYString is a concatenation of two big.Int decimal
// renderings, so SetString cannot fail on a non-nil input. The line is
// effectively unreachable; if a future refactor breaks the invariant,
// the resulting nil PublicKeyInteger would crash on `.Text(49)` with a
// clear stack trace rather than silently produce a wrong address.
func AffineToPublicKey(Input CoordAffine) string {
    if Input.AX == nil || Input.AY == nil {
        panic(fmt.Sprintf("AffineToPublicKey: nil coordinate (AX==nil: %v, AY==nil: %v)", Input.AX == nil, Input.AY == nil))
    }
    XString := Input.AX.String()                             //X Coordinates as string
    XStringLength := int64(len(XString))                     //Length of the XString
    XStringLengthBig := new(big.Int).SetInt64(XStringLength) //Length of the XString as big.Int
    PublicKeyPrefix := XStringLengthBig.Text(49)             //Converted to Base 49
    //The Public-Key PublicKeyPrefix in Baase 49 is needed to reconstruct
    //The Public Key Affine Coordinates from the PublicKey String

    YString := Input.AY.String()
    XYString := XString + YString
    PublicKeyInteger, _ := new(big.Int).SetString(XYString, 10)
    PublicKey := PublicKeyInteger.Text(49)
    PrefixedPublicKey := PublicKeyPrefix + "." + PublicKey
    return PrefixedPublicKey
}

// VI Key Generation
//
// REQ-10 (T4.1): replaced the prior per-bit `rand.Int(rand.Reader, Two)` loop
// (e.S calls into crypto/rand for a one-bit BigInt each) with a single bulk
// `rand.Read` of ceil(e.S / 8) bytes followed by an MSB-first bit-render loop.
// For DALOS S=1600 this is one 200-byte syscall instead of 1600 BigInt ops.
// crypto/rand.Read is documented to never return a short read on success, and
// any error is unrecoverable (entropy source failure) so we panic — consistent
// with the existing key-gen invariants where partial randomness would silently
// corrupt the generated private key.
//
// Output API unchanged: returns a string of length exactly e.S consisting of
// '0' and '1' runes. Genesis byte-identity is preserved because the testvector
// generator uses a separate seeded math/rand path (testvectors/generator/main.go
// randomBitString), not this function.
func (e *Ellipse) GenerateRandomBitsOnCurve() string {
    var (
        bitLength     = e.S
        binaryBuilder strings.Builder
    )
    binaryBuilder.Grow(int(bitLength))

    byteLen := (int(bitLength) + 7) / 8
    buf := make([]byte, byteLen)
    if _, err := rand.Read(buf); err != nil {
        panic(fmt.Sprintf("GenerateRandomBitsOnCurve: rand.Read failed: %v", err))
    }

    for i := 0; i < int(bitLength); i++ {
        byteIdx := i / 8
        bitIdx := 7 - (i % 8)
        if (buf[byteIdx]>>bitIdx)&1 == 1 {
            binaryBuilder.WriteByte('1')
        } else {
            binaryBuilder.WriteByte('0')
        }
    }
    return binaryBuilder.String()
}

// SeedWordsToBitString derives a bitstring from seed words. This is the
// single production entry point for seed-word-based key generation in
// the Go reference — every real caller (the CLI's -seed flag, the
// testvector generator, any future consumer) goes through here, which
// is why the seed-word contract (ValidateSeedWords: 1-256 words, each
// 1-256 glyphs, every glyph in the 256-glyph DALOS CharacterMatrix) is
// enforced right here rather than left to each caller to remember.
func (e *Ellipse) SeedWordsToBitString(SeedWords []string) (string, error) {
    if err := ValidateSeedWords(SeedWords); err != nil {
        return "", err
    }
    JoinedSeeds := strings.Join(SeedWords, " ")
    JoinedSeedsToByteSlice := []byte(JoinedSeeds)
    //Compute the Blake3 SumCustom output size. The safe-scalar size is NOT
    //required to be a multiple of eight — `aux.CeilDiv8` enforces ceiling
    //semantics so byte-aligned curves (DALOS S=1600, APOLLO S=1024) and
    //non-byte-aligned curves (LETO S=545, ARTEMIS S=1023) all produce a valid byte-count.
    OutputSize := aux.CeilDiv8(int(e.S))
    //SevenFoldHash
    Hash1 := Blake3.SumCustom(JoinedSeedsToByteSlice, OutputSize)
    Hash2 := Blake3.SumCustom(Hash1, OutputSize)
    Hash3 := Blake3.SumCustom(Hash2, OutputSize)
    Hash4 := Blake3.SumCustom(Hash3, OutputSize)
    Hash5 := Blake3.SumCustom(Hash4, OutputSize)
    Hash6 := Blake3.SumCustom(Hash5, OutputSize)
    Hash7 := Blake3.SumCustom(Hash6, OutputSize)
    return e.ConvertHashToBitString(Hash7), nil
}

// ConvertHashToBitString renders Hash as a big-endian bitstring of e.S bits, mirroring
// the TypeScript canonical at ts/src/gen1/hashing.ts:108-129 (convertHashToBitString).
// XCURVE-4: replaces the prior hex->big.Int->Text(2) pipeline that elided leading zeros.
//
// HARDENING (v4.0.2, audit cycle 2026-05-04, F-MED-010): the pre-v4.0.2
// loop body was `full += fmt.Sprintf("%08b", b)` — Go strings are
// immutable, so this allocated a new backing array and copied the
// running result on EVERY byte. For DALOS (200-byte hash → 1600-char
// bitstring) that's 200 allocs of 8/16/24/.../1600 bytes ≈ 160KB total
// for what should be a 1600-byte output. The same file already
// demonstrates the correct pattern in `GenerateRandomBitsOnCurve`
// (line 168 area) using `strings.Builder.Grow` — adopted here for
// consistency. Genesis byte-identity preserved (same bytes written in
// the same order, just to a pre-grown buffer instead of via repeated
// re-allocations).
func (e *Ellipse) ConvertHashToBitString(Hash []byte) string {
    var b strings.Builder
    b.Grow(len(Hash) * 8)
    for _, by := range Hash {
        // Inline the 8-bit big-endian render. Faster than fmt.Sprintf
        // ("%08b") which allocates a temporary string per call; the
        // bit-shift loop writes directly into the builder.
        for bit := 7; bit >= 0; bit-- {
            if (by>>bit)&1 == 1 {
                b.WriteByte('1')
            } else {
                b.WriteByte('0')
            }
        }
    }
    full := b.String()
    bitLength := int(e.S)
    if len(full) == bitLength {
        return full
    }
    if len(full) > bitLength {
        return full[:bitLength]
    }
    return strings.Repeat("0", bitLength-len(full)) + full
}

func (e *Ellipse) ValidateBitString(BitString string) (bool, bool, bool) {
    // Check if the length of the string matches k.S
    var (
        LengthBoolean, StructureBoolean, TotalBoolean bool
    )
    if uint32(len(BitString)) == e.S {
        LengthBoolean = true
    }
    // Check if the string contains only '0' and '1'
    StructureBoolean = true // Start by assuming it's true
    for _, char := range BitString {
        if char != '0' && char != '1' {
            StructureBoolean = false
            break
        }
    }
    // Overall truth depends on both length and structure
    TotalBoolean = LengthBoolean && StructureBoolean
    return TotalBoolean, LengthBoolean, StructureBoolean
}

// ValidatePrivateKey checks if the given private key as big.Int string meets the specified conditions.
// The input can be in either base 10 (when isBase10 is true) or base 49 (when isBase10 is false).
// Returns (valid, bitString, reason):
//   - valid: true if all checks pass
//   - bitString: the trimmed middle bit-string on success, "" on failure
//   - reason: empty on success, descriptive failure reason on validation rejection
//
// HARDENING (v4.0.2, audit cycle 2026-05-04, F-MED-016): the pre-v4.0.2
// implementation called `fmt.Println` from inside this method, breaking
// the Phase 10 / REQ-31 pure-crypto invariant on the Elliptic/ package
// (library code must not write to stdout — non-CLI consumers cannot
// suppress those prints). Refactored to surface the failure reason via
// a third return value; callers (process.go, ScalarToPrivateKey)
// render the reason themselves. Mirrors the TS port's `validateBitmap`
// `{ valid, reason? }` shape (per `ts/src/gen1/bitmap.ts`).
func (e *Ellipse) ValidatePrivateKey(privateKey string, isBase10 bool) (valid bool, bitString string, reason string) {
    var binaryKey string
    PK := new(big.Int)

    // Convert the private key to binary string representation
    if isBase10 {
        PK.SetString(privateKey, 10)
        binaryKey = PK.Text(2) // Convert the Big.Int to binary string
    } else {
        PK.SetString(privateKey, 49)
        binaryKey = PK.Text(2) // Convert the Big.Int to binary string
    }

    // Check if the first character is '1'
    if len(binaryKey) == 0 || binaryKey[0] != '1' {
        return false, "", "binary representation does not have '1' as first digit"
    }

    // Get the binary representation of the cofactor
    cofactorBinary := e.R.Text(2)

    // Check if the last two digits match the last two digits of the cofactor's binary representation
    if len(binaryKey) < 2 || binaryKey[len(binaryKey)-2:] != cofactorBinary[len(cofactorBinary)-2:] {
        return false, "", fmt.Sprintf("binary representation does not match the Ellipse cofactor with its last %d digits (must be zero)", len(cofactorBinary)-1)
    }

    // Check the length of the middle part
    middleLength := len(binaryKey) - len(cofactorBinary) // Exclude first and last digits
    if uint32(middleLength) != e.S {
        return false, "", fmt.Sprintf("core binary representation must be %d digits long (got %d)", e.S, middleLength)
    }

    // Extract and return the BitString (the middle part)
    bitString = binaryKey[1 : len(binaryKey)-(len(cofactorBinary)-1)] // Trim the first and last parts
    return true, bitString, ""
}

//Private Key can be represented as:
//  A BitString, 1600 digits long. This must be clamped, according to curve cofactor to generate the Int(base10) or INT(base49)
//  Clamping According to Dalos Curve, means adding a prefix of 1(before the BitString), and a Suffix of 00 (after the bitstring)
//  The resulted BitString 1603 digits long is converted to Big.Int(base10) or BigInt(base49)
//      Note: The Bits displayed when generating a Key Pair, are alredy clamped 1603 digits long.
//      To use them to regenerate Key pair, remove the first bit and the last 2 bits, to get the Original BitString
//
//  A BigInt(base10), created as depicted above from the BitString 1600 Digits Long. This is the Scalar.
//  A BigInt(base49), created as depicted above from the BitString 1600 Digits Long. This is the Scalar.

func (e *Ellipse) GenerateScalarFromBitString(BitString string) (*big.Int, error) {
    //Clamps a BitString according to Curve Cofactor, generating a Scalar from it.
    //Throws an error if the BitString is not a Valid String of Bits, equal in length the Curves Safe Scalar size
    // Validates the BitString
    if isValid, _, _ := e.ValidateBitString(BitString); !isValid {
        return nil, errors.New("the bitstring is invalid for the " + e.Name + " Curve")
    }
    // Get the binary representation of the cofactor
    BinaryCofactor := e.R.Text(2)
    if len(BinaryCofactor) > 0 {
        // Trim the first rune of the binary cofactor
        BinaryCofactor = aux.TrimFirstRune(BinaryCofactor)
    }
    // Construct the final binary string
    BinaryString := "1" + BitString + BinaryCofactor
    // Convert the final binary string to a big.Int
    Scalar := new(big.Int)
    Scalar.SetString(BinaryString, 2)
    return Scalar, nil
}

func (e *Ellipse) ScalarToKeys(Scalar *big.Int) (DalosKeyPair, error) {
    var Output DalosKeyPair
    
    // Attempt to convert the scalar to a private key
    PrivateKey, err := e.ScalarToPrivateKey(Scalar)
    if err != nil {
        return Output, err // Return an error if the private key is invalid
    }
    
    // Set the private key and compute the public key
    Output.PRIV = PrivateKey.Int49
    Output.PUBL = e.ScalarToPublicKey(Scalar)
    
    return Output, nil // Return the key pair and nil error
}

func (e *Ellipse) ScalarToPrivateKey(Scalar *big.Int) (DalosPrivateKey, error) {
    var Output DalosPrivateKey
    ScalarAsStringAkaPrivateKeyInDecimal := Scalar.Text(10)
    
    // Validate the private key
    // F-MED-016 (v4.0.2): ValidatePrivateKey now returns reason as the
    // third value; we wrap it into the error message so callers see
    // the specific failure cause instead of the pre-fix stdout print.
    isValid, BitString, reason := e.ValidatePrivateKey(ScalarAsStringAkaPrivateKeyInDecimal, true)

    // Only proceed if the key is valid
    if isValid {
        Output.BitString = BitString   // Middle part of the representation
        Output.Int10 = Scalar.Text(10) // Base 10 representation
        Output.Int49 = Scalar.Text(49) // Base 49 representation
        return Output, nil             // Success case
    }

    // Return an error if validation fails (reason from ValidatePrivateKey).
    return Output, fmt.Errorf("invalid private key: %s", reason)
}

func (e *Ellipse) ScalarToPublicKey(Scalar *big.Int) string {
    PublicKeyPointsExtended := e.ScalarMultiplierWithGenerator(Scalar)
    PublicKeyPointsAffine := e.Extended2Affine(PublicKeyPointsExtended)
    PrefixedPublicKey := AffineToPublicKey(PublicKeyPointsAffine)
    return PrefixedPublicKey
}

// GenerateFromBitmap is the 6th key-generation input path (added in v1.2.0).
//
// A 40x40 black/white Bitmap encodes exactly 1600 bits — the DALOS safe-scalar
// size. The bitmap is converted to a bitstring via row-major top-to-bottom,
// left-to-right scan (black=1, white=0), then the standard pipeline produces
// the scalar, private key and public key.
//
// This function is pure input reshaping — no new cryptographic operations are
// introduced. It is equivalent to:
//
//     bits := Bitmap.BitmapToBitString(b)
//     scalar, err := e.GenerateScalarFromBitString(bits)
//     keys, err := e.ScalarToKeys(scalar)
//
// Returns the computed key pair or an error if the intermediate bitstring
// fails validation (which cannot happen for a structurally valid Bitmap).
func (e *Ellipse) GenerateFromBitmap(b Bitmap.Bitmap) (DalosKeyPair, error) {
    var zero DalosKeyPair
    // Bitmap.ValidateBitmap is a documented no-op (F-API-006, v4.0.1) —
    // reserved hook for future structural validation. The Go type system
    // already enforces the structural-validity invariants this function
    // could otherwise check. Kept here as a forward-compat anchor: any
    // future real check added to ValidateBitmap will fire automatically
    // at this call site without a downstream API change.
    if err := Bitmap.ValidateBitmap(b); err != nil {
        return zero, fmt.Errorf("invalid bitmap: %w", err)
    }
    bits := Bitmap.BitmapToBitString(b)
    scalar, err := e.GenerateScalarFromBitString(bits)
    if err != nil {
        return zero, fmt.Errorf("bitmap produced invalid bitstring: %w", err)
    }
    return e.ScalarToKeys(scalar)
}

// Phase 10 (REQ-31, v4.0.0): The following symbols moved out of this
// package to enforce the pure-crypto invariant on Elliptic/ —
//   - PrintKeys, PrintPrivateKey            -> ../print.go (package main)
//   - ProcessIntegerFlag,
//     ProcessPrivateKeyConversion,
//     ProcessKeyGeneration,
//     SaveBitString                          -> ../process.go (package main)
//   - ExportPrivateKey, ImportPrivateKey,
//     AESDecrypt,
//     GenerateFilenameFromPublicKey          -> ../keystore/ (NEW package)
// All retain output-preserving behaviour; the receivers were rewritten
// from `(e *Ellipse)` methods to free functions taking `e *el.Ellipse`
// because Go forbids defining methods on types from external packages.
// See ../.bee/specs/2026-05-02-unified-audit-2026-04-29/phases/
// 10-elliptic-package-carve-out/MIGRATION.md for the full migration table.


// CharacterMatrix family carved out to Elliptic/CharacterMatrix.go in
// v4.0.3 (F-LOW-012, audit cycle 2026-05-04). The 297-line static rune
// table dominated this file (~38% of total LoC) and is conceptually
// unrelated to key-generation logic — it's a constant lookup table.
// See CharacterMatrix.go for the cache var, accessor, and the table
// builder. Byte-identical to the pre-v4.0.3 inline form.
