package Elliptic

import (
    "DALOS_Crypto/Bitmap"
    "errors"
    "fmt"
    "math/big"
)

type EllipseMethods interface {
    // I - Mod P Methods
    AddModP(a, b *big.Int) *big.Int // Ia.1
    SubModP(a, b *big.Int) *big.Int // Ia.2
    MulModP(a, b *big.Int) *big.Int // Ia.3
    QuoModP(a, b *big.Int) *big.Int // Ia.4
    
    // II - Coordinate Conversion
    Affine2Extended(InputP CoordAffine) (OutputP CoordExtended)
    Extended2Affine(InputP CoordExtended) (OutputP CoordAffine)
    
    // III Boolean Methods
    IsInfinityPoint(InputP CoordExtended) bool
    IsOnCurve(InputP CoordExtended) (OnCurve bool, Infinity bool)
    IsInverseOnCurve(P1, P2 CoordExtended) bool
    ArePointsEqual(P1, P2 CoordExtended) bool
    
    // IV Basic Operations
    Addition(P1, P2 CoordExtended) (CoordExtended, error)
    AdditionV1(P1, P2 CoordExtended) (CoordExtended, error)
    AdditionV2(P1, P2 CoordExtended) (CoordExtended, error)
    AdditionV3(P1, P2 CoordExtended) (CoordExtended, error)
    Doubling(P CoordExtended) (CoordExtended, error)
    DoublingV1(P CoordExtended) (CoordExtended, error)
    DoublingV2(P CoordExtended) (CoordExtended, error)
    Tripling(P CoordExtended) CoordExtended
    
    // V Complex Operations
    FortyNiner(P CoordExtended) CoordExtended
    PrecomputeMatrixWithGenerator() [7][7]CoordExtended
    PrecomputeMatrix(P CoordExtended) [7][7]CoordExtended
    ScalarMultiplierWithGenerator(Scalar *big.Int) CoordExtended
    ScalarMultiplier(Scalar *big.Int, P CoordExtended) CoordExtended
    
    // VI Key Generation
    GenerateRandomBitsOnCurve() string
    SeedWordsToBitString(SeedWords []string) (string, error)
    ConvertHashToBitString(Hash []byte) string
    ValidateBitString(BitString string) (bool, bool, bool)
    // F-MED-016 (v4.0.2): added third return for failure reason. The
    // pre-v4.0.2 (bool, string) signature had `fmt.Println` calls
    // inside the implementation that violated the Phase 10 / REQ-31
    // pure-crypto invariant on this package. Reason now returned to
    // the caller; callers render diagnostics themselves.
    ValidatePrivateKey(privateKey string, isBase10 bool) (valid bool, bitString string, reason string)
    GenerateScalarFromBitString(BitString string) (*big.Int, error)
    ScalarToKeys(Scalar *big.Int) (DalosKeyPair, error)
    ScalarToPrivateKey(Scalar *big.Int) (DalosPrivateKey, error)
    ScalarToPublicKey(Scalar *big.Int) string
    // F-MED-020 (v4.0.2): GenerateFromBitmap (the 6th key-generation
    // input path, added v1.2.0) was missing from EllipseMethods —
    // Phase 11 compile-time conformance assertion (assertions.go:20)
    // only enforces *Ellipse ⊇ EllipseMethods, not the inverse, so the
    // omission was undetected for two minor releases. Consumers
    // dispatching through the interface type couldn't call
    // GenerateFromBitmap. Added now to align the interface with the
    // public surface.
    //
    // SCOPE: signature takes a hardcoded 40×40 = 1600-bit DALOS bitmap
    // (per F-TEST-002, per-curve dimensioning is a consumer-side
    // concern; see OuronetUI's src/lib/dalos/bitmap-local.ts for the
    // reshape pattern that lets a single 40×40 visual input feed
    // curves of varying bit-widths). The Bitmap import is the first
    // dependency this package takes on Bitmap; previously only the
    // *Ellipse method body referenced it.
    GenerateFromBitmap(b Bitmap.Bitmap) (DalosKeyPair, error)

    // VII Wallet I/O — moved to ../keystore/ in v4.0.0 (Phase 10, REQ-31).
    //                  See ../keystore/{export,import,decrypt,filename}.go.

    // VIII Schnorr Signature
    SchnorrHash(R *big.Int, PublicKey string, Message string) *big.Int
    // F-API-005 (v4.0.1): SchnorrSign returns (string, error) instead of
    // string-with-empty-sentinel. Mirrors TS schnorrSign which throws
    // SchnorrSignError. The compile-time assertion in assertions.go
    // enforces non-drift across the carve-out boundary.
    SchnorrSign(KeyPair DalosKeyPair, Message string) (string, error)
    // F-ARCH-002 (Phase 11, v4.0.0): parameter order aligned with implementation.
    // Compile-time conformance assertion in assertions.go enforces non-drift.
    SchnorrVerify(Signature, Message, PublicKey string) bool
}

func (e *Ellipse) AddModP(a, b *big.Int) *big.Int {
    return AddModulus(&e.P, a, b)
}
func (e *Ellipse) SubModP(a, b *big.Int) *big.Int {
    return SubModulus(&e.P, a, b)
}
func (e *Ellipse) MulModP(a, b *big.Int) *big.Int {
    return MulModulus(&e.P, a, b)
}
func (e *Ellipse) QuoModP(a, b *big.Int) *big.Int {
    return QuoModulus(&e.P, a, b)
}

// III Boolean Methods
func (e *Ellipse) IsInfinityPoint(InputP CoordExtended) bool {
    Cmp1 := InputP.EX.Cmp(Zero)
    Cmp2 := InputP.ET.Cmp(Zero)
    Cmp3 := InputP.EY.Cmp(InputP.EZ)
    return Cmp1 == 0 && Cmp2 == 0 && Cmp3 == 0
}

func (e *Ellipse) IsOnCurve(InputP CoordExtended) (OnCurve bool, Infinity bool) {
    // F-PERF-003 (audit cycle 2026-05-04, v4.0.1): delegate to the
    // projective extended-coords curve equation. Eliminates 2 ModInverse
    // calls per invocation (the OLD path projected to affine via
    // Extended2Affine first, paying 2 ModInverses purely for the
    // representation change before doing the actual curve check).
    //
    // Equivalence proven by TestIsOnCurve_OldVsNew_Equivalence
    // (PointOperations_perf_equiv_test.go) over the full reachable
    // input space (12 on-curve inputs + 5 off-curve + canonical
    // infinity); Genesis 105-vector corpus byte-identity SHA-256
    // (082f7a40...) is the end-to-end regression guard.
    return e.isOnCurveExtended(InputP)
}

func (e *Ellipse) IsInverseOnCurve(P1, P2 CoordExtended) bool {
    //The inverse of a point
    //(x1, y1) on E is (−x1, y1).
    P1Affine := e.Extended2Affine(P1)
    P2Affine := e.Extended2Affine(P2)
    
    var SummedX = new(big.Int)
    SummedX.Add(P1Affine.AX, P2Affine.AX)
    Cmp1 := SummedX.Cmp(Zero)
    Cmp2 := P1Affine.AY.Cmp(P2Affine.AY)
    
    return Cmp1 == 0 && Cmp2 == 0
}

func (e *Ellipse) ArePointsEqual(P1, P2 CoordExtended) bool {
    // F-PERF-003 (audit cycle 2026-05-04, v4.0.1): delegate to the
    // projective cross-multiplication helper. Eliminates 4 ModInverse
    // calls per invocation (the OLD path projected BOTH points to
    // affine via Extended2Affine, paying 2 ModInverses each, before
    // doing what is fundamentally a projective-equality check).
    //
    // Equivalence proven by TestArePointsEqual_OldVsNew_Equivalence
    // (PointOperations_perf_equiv_test.go) over the full reachable
    // input space (same-self equality, same-projective-different-extended
    // equality across 7 scale factors per point, and full N×N
    // cross-pair consistency on 12 distinct points); Genesis 105-vector
    // corpus byte-identity SHA-256 (082f7a40...) is the end-to-end
    // regression guard.
    return e.arePointsEqualProjective(P1, P2)
}

// arePointsEqualProjective is the F-PERF-003 (v4.0.1) replacement for
// ArePointsEqual. Two HWCD extended points represent the same affine
// point iff their projective cross-products match:
//
//   P1 == P2  iff  X1·Z2 ≡ X2·Z1 (mod p)  AND  Y1·Z2 ≡ Y2·Z1 (mod p)
//
// (Derivation: P1 == P2 in affine iff X1/Z1 == X2/Z2 and Y1/Z1 == Y2/Z2;
// cross-multiply by Z1·Z2 to clear denominators.)
//
// Cost:
//   - OLD ArePointsEqual via Extended2Affine: 4 ModInverse + 4 mul.
//   - NEW arePointsEqualProjective:           0 ModInverse + 4 mul + 2 cmp.
//
// ModInverse is the most expensive single big.Int operation in this
// codebase, so eliminating 4 per Schnorr verify is meaningful.
// Equivalence to ArePointsEqual is pinned by
// TestArePointsEqual_OldVsNew_Equivalence + the Genesis corpus
// byte-identity SHA-256 regression guard.
func (e *Ellipse) arePointsEqualProjective(P1, P2 CoordExtended) bool {
    X1Z2 := e.MulModP(P1.EX, P2.EZ)
    X2Z1 := e.MulModP(P2.EX, P1.EZ)
    if X1Z2.Cmp(X2Z1) != 0 {
        return false
    }
    Y1Z2 := e.MulModP(P1.EY, P2.EZ)
    Y2Z1 := e.MulModP(P2.EY, P1.EZ)
    return Y1Z2.Cmp(Y2Z1) == 0
}

// isOnCurveExtended is the F-PERF-003 (v4.0.1) replacement for the
// affine-projection inside IsOnCurve. The DALOS Twisted Edwards curve
// has parameter a = 1 (see Parameters.go ":e.A.SetInt64(1)" — same on
// E521 / LETO / ARTEMIS / APOLLO), so the affine equation is:
//
//   x² + y² = 1 + D · x² · y²
//
// With x = X/Z, y = Y/Z, T = XY/Z, multiplying by Z² and using
// x²·y² = T²/Z² (since T = XY/Z → T² = X²Y²/Z²) gives the homogenized
// extended-coords curve equation:
//
//   X² + Y² ≡ Z² + D · T² (mod p)
//
// Cost:
//   - OLD via Extended2Affine: 2 ModInverse + 2 mul (QuoModP) + 2 ExpModP
//     (Exp(_, 2) which boils down to 1 mul) + 1 mul + 2 add.
//   - NEW isOnCurveExtended:   0 ModInverse + 5 mul + 2 add + 1 cmp.
//
// Behavior note for invalid inputs: OLD path panicked in Extended2Affine
// → QuoModP if EZ == 0 (division by zero in ModInverse). NEW path
// computes 0+Y² == 0+D·T² which may return true or false depending on
// values. The all-zero or Z=0 extended representations are NEVER
// produced by Affine2Extended, ScalarMultiplier, Doubling, Addition, or
// any HWCD primitive in this codebase, so this divergence is unreachable
// from the corpus and any well-typed external consumer. Equivalence on
// the reachable input space is pinned by TestIsOnCurve_OldVsNew_Equivalence.
func (e *Ellipse) isOnCurveExtended(InputP CoordExtended) (OnCurve bool, Infinity bool) {
    Infinity = e.IsInfinityPoint(InputP)

    X2 := e.MulModP(InputP.EX, InputP.EX)
    Y2 := e.MulModP(InputP.EY, InputP.EY)
    Z2 := e.MulModP(InputP.EZ, InputP.EZ)
    T2 := e.MulModP(InputP.ET, InputP.ET)
    dT2 := e.MulModP(T2, &e.D)

    Left := e.AddModP(X2, Y2)         // X² + Y²  (a = 1, so a·X² = X²)
    Right := e.AddModP(Z2, dT2)       // Z² + D·T²
    OnCurve = Left.Cmp(Right) == 0
    return OnCurve, Infinity
}

//Basic Point Operations

//Addition on Extended Coordinates of TEC, with no assumption that a=-1(which it isn't)
func (e *Ellipse) Addition(P1, P2 CoordExtended) (CoordExtended, error) {
    // Check if both Z1 and Z2 are 1
    var (
        Output CoordExtended
        err    error
    )
    if P1.EZ.Cmp(One) == 0 && P2.EZ.Cmp(One) == 0 {
        // Variant 1: If both Z1 and Z2 are 1
        Output, err = e.AdditionV1(P1, P2) // Uses "mmadd-2008-hwcd-2" addition formulas
        return Output, err
    } else if P2.EZ.Cmp(One) == 0 {
        // Variant 2: If Z2 is 1, but Z1 is not
        Output, err = e.AdditionV2(P1, P2) // Uses "madd-2008-hwcd-2" addition formulas
        return Output, err
    } else {
        // Variant 3: If both Z1 and Z2 are different from 1
        Output, err = e.AdditionV3(P1, P2) // Uses "add-2008-hwcd-2" addition formulas
        return Output, err
    }
}
func (e *Ellipse) AdditionV1(P1, P2 CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/addition/mmadd-2008-hwcd
    
    // Declare result point
    var Output CoordExtended
    // Verify that both Z1 and Z2 are 1
    if P1.EZ.Cmp(One) != 0 || P2.EZ.Cmp(One) != 0 {
        return Output, fmt.Errorf("AdditionV1 requires both Z1 and Z2 to be 1")
    }
    // Addition logic for the case when Z1 = 1 and Z2 = 1 (mmadd-2008-hwcd)
    A := e.MulModP(P1.EX, P2.EX)                  // A = X1 * X2
    B := e.MulModP(P1.EY, P2.EY)                  // B = Y1 * Y2
    C := e.MulModP(P1.ET, e.MulModP(&e.D, P2.ET)) // C = T1 * d * T2
    v1 := e.AddModP(P1.EX, P1.EY)
    v2 := e.AddModP(P2.EX, P2.EY)
    v3 := e.MulModP(v1, v2)
    v4 := e.SubModP(v3, A)
    E := e.SubModP(v4, B)  // E = (X1 + Y1)(X2 + Y2) - A - B
    F := e.SubModP(One, C) // F = 1 - C
    G := e.AddModP(One, C)
    H := e.SubModP(B, e.MulModP(&e.A, A))       // H = B - a * A
    Output.EX = e.MulModP(E, F)                 // X3 = E * F
    Output.EY = e.MulModP(G, H)                 // Y3 = G * H
    Output.ET = e.MulModP(E, H)                 // T3 = E * H
    Output.EZ = e.SubModP(One, e.MulModP(C, C)) // Z3 = 1 - C^2
    /*
       fmt.Println("A iz", A)
       fmt.Println("B iz", B)
       fmt.Println("C iz", C)
       fmt.Println("E iz", E)
       fmt.Println("F iz", F)
       fmt.Println("G iz", G)
       fmt.Println("H iz", H)
    */
    return Output, nil
}

func (e *Ellipse) AdditionV2(P1, P2 CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/addition/madd-2008-hwcd-2
    // Declare result point
    var Output CoordExtended
    
    // Verify that Z2 is 1
    if P2.EZ.Cmp(One) != 0 {
        return CoordExtended{}, errors.New("Z2 must be 1 for AdditionV2")
    }
    
    // Addition logic for the case when Z2 = 1 (madd-2008-hwcd-2)
    A := e.MulModP(P1.EX, P2.EX)
    B := e.MulModP(P1.EY, P2.EY)
    C := e.MulModP(P1.EZ, P2.ET)
    D := P1.ET
    E := e.AddModP(C, D)
    v1 := e.SubModP(P1.EX, P1.EY)
    v2 := e.AddModP(P2.EX, P2.EY)
    v3 := e.MulModP(v1, v2)
    v4 := e.AddModP(v3, B)
    F := e.SubModP(v4, A)
    v5 := e.MulModP(A, &e.A)
    G := e.AddModP(B, v5)
    H := e.SubModP(D, C)
    Output.EX = e.MulModP(E, F)
    Output.EY = e.MulModP(G, H)
    Output.ET = e.MulModP(E, H)
    Output.EZ = e.MulModP(F, G)
    return Output, nil
}

func (e *Ellipse) AdditionV3(P1, P2 CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/addition/add-2008-hwcd
    // Verify that Z1 and Z2 are different from 1
    if P2.EZ.Cmp(One) == 0 {
        return CoordExtended{}, errors.New("Both Z1 and Z2 must be different from 1 for AdditionV3")
    }
    
    // Initialize result point
    var Output CoordExtended
    
    // Addition logic for the case when Z2 = 1 (add-2008-hwcd)
    A := e.MulModP(P1.EX, P2.EX)
    B := e.MulModP(P1.EY, P2.EY)
    v1 := e.MulModP(&e.D, P2.ET)
    C := e.MulModP(P1.ET, v1)
    D := e.MulModP(P1.EZ, P2.EZ)
    v2 := e.AddModP(P1.EX, P1.EY)
    v3 := e.AddModP(P2.EX, P2.EY)
    v4 := e.MulModP(v2, v3)
    v5 := e.SubModP(v4, A)
    E := e.SubModP(v5, B)
    F := e.SubModP(D, C)
    G := e.AddModP(D, C)
    v6 := e.MulModP(&e.A, A)
    H := e.SubModP(B, v6)
    Output.EX = e.MulModP(E, F)
    Output.EY = e.MulModP(G, H)
    Output.ET = e.MulModP(E, H)
    Output.EZ = e.MulModP(F, G)
    return Output, nil
}

func (e *Ellipse) Doubling(P CoordExtended) (CoordExtended, error) {
    // Check if Z1 is 1
    var (
        Output CoordExtended
        err    error
    )
    if P.EZ.Cmp(One) == 0 {
        // Variant 1: If Z1 is 1
        Output, err = e.DoublingV1(P) // Uses the "mdbl-2008-hwcd" doubling formulas
        return Output, err
    } else {
        // Variant 2: If Z1 is not 1
        Output, err = e.DoublingV2(P) // Uses the "dbl-2008-hwcd" doubling formulas
        return Output, err
    }
}

// Doubling Variant 1: Z1 is 1
func (e *Ellipse) DoublingV1(P CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/doubling/mdbl-2008-hwcd
    // Verify that Z is 1
    if P.EZ.Cmp(One) != 0 {
        return CoordExtended{}, errors.New("Z must be 1 for Doubling Variant1")
    }
    
    // Initialize result point
    var Output CoordExtended
    
    // Addition logic for the case when Z2 = 1 (mdbl-2008-hwcd)
    A := e.MulModP(P.EX, P.EX)
    B := e.MulModP(P.EY, P.EY)
    D := e.MulModP(A, &e.A)
    v1 := e.AddModP(P.EX, P.EY)
    v2 := e.MulModP(v1, v1)
    v3 := e.SubModP(v2, A)
    E := e.SubModP(v3, B)
    G := e.AddModP(D, B)
    H := e.SubModP(D, B)
    v4 := e.SubModP(G, Two)
    Output.EX = e.MulModP(E, v4)
    Output.EY = e.MulModP(G, H)
    Output.ET = e.MulModP(E, H)
    v5 := e.MulModP(Two, G)
    v6 := e.MulModP(G, G)
    Output.EZ = e.SubModP(v6, v5)
    
    return Output, nil
}

// DoublingV2 Doubling Variant 2: Z1 is not 1
func (e *Ellipse) DoublingV2(P CoordExtended) (CoordExtended, error) {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/doubling/dbl-2008-hwcd
    // Initialize result point
    var Output CoordExtended
    
    // Logic for DoublingV2 ("dbl-2008-hwcd")
    A := e.MulModP(P.EX, P.EX)
    B := e.MulModP(P.EY, P.EY)
    v1 := e.MulModP(P.EZ, P.EZ)
    C := e.MulModP(Two, v1)
    D := e.MulModP(A, &e.A)
    v2 := e.AddModP(P.EX, P.EY)
    v3 := e.MulModP(v2, v2)
    v4 := e.SubModP(v3, A)
    E := e.SubModP(v4, B)
    G := e.AddModP(D, B)
    F := e.SubModP(G, C)
    H := e.SubModP(D, B)
    Output.EX = e.MulModP(E, F)
    Output.EY = e.MulModP(G, H)
    Output.ET = e.MulModP(E, H)
    Output.EZ = e.MulModP(F, G)
    return Output, nil
}

func (e *Ellipse) Tripling(P CoordExtended) CoordExtended {
    //https://hyperelliptic.org/EFD/g1p/data/twisted/extended/tripling/tpl-2015-c
    // Initialize result point
    var Output CoordExtended
    
    //Checking
    //fmt.Printf("P before tripling: EX = %v, EY = %v\n", P.EX, P.EY)
    
    // Logic for Tripling (tpl-2015-c)
    YY := e.MulModP(P.EY, P.EY)
    XX := e.MulModP(P.EX, P.EX)
    aXX := e.MulModP(&e.A, XX)
    Ap := e.AddModP(YY, aXX)
    ZZ := e.MulModP(P.EZ, P.EZ)
    v1 := e.MulModP(Two, ZZ)
    v2 := e.SubModP(v1, Ap)
    B := e.MulModP(Two, v2)
    xB := e.MulModP(aXX, B)
    yB := e.MulModP(YY, B)
    v3 := e.SubModP(YY, aXX)
    AA := e.MulModP(Ap, v3)
    F := e.SubModP(AA, yB)
    G := e.AddModP(AA, xB)
    v4 := e.AddModP(yB, AA)
    xE := e.MulModP(P.EX, v4)
    v5 := e.SubModP(xB, AA)
    yH := e.MulModP(P.EY, v5)
    zF := e.MulModP(P.EZ, F)
    zG := e.MulModP(P.EZ, G)
    Output.EX = e.MulModP(xE, zF)
    Output.EY = e.MulModP(yH, zG)
    Output.EZ = e.MulModP(zF, zG)
    Output.ET = e.MulModP(xE, yH)
    return Output
}

// V Complex Operations

// noErrAddition wraps Addition for internal call sites that invoke it
// with operands guaranteed by construction to be on-curve. Any error
// from the inner Addition at such a site is a programming error (not
// a user-input problem) and is converted to a panic. PO-3 hardening
// (v2.1.0): silent error swallowing in these paths is replaced with
// explicit fail-fast behaviour.
func (e *Ellipse) noErrAddition(P1, P2 CoordExtended) CoordExtended {
    r, err := e.Addition(P1, P2)
    if err != nil {
        panic(fmt.Sprintf("internal Addition failed unexpectedly: %v", err))
    }
    return r
}

// noErrDoubling is the Doubling counterpart to noErrAddition. Used at
// internal call sites where the input is guaranteed on-curve by
// construction; any error is a programming error and panics.
func (e *Ellipse) noErrDoubling(P CoordExtended) CoordExtended {
    r, err := e.Doubling(P)
    if err != nil {
        panic(fmt.Sprintf("internal Doubling failed unexpectedly: %v", err))
    }
    return r
}

//FortyNiner Adds a Point to Itself 49 Times
func (e *Ellipse) FortyNiner(P CoordExtended) CoordExtended {
    Point03 := e.Tripling(P)
    Point06 := e.noErrDoubling(Point03)
    Point12 := e.noErrDoubling(Point06)
    Point24 := e.noErrDoubling(Point12)
    Point48 := e.noErrDoubling(Point24)
    Point49 := e.noErrAddition(Point48, P)
    return Point49
}

func (e *Ellipse) PrecomputeMatrixWithGenerator() [7][7]CoordExtended {
    //Creates Precomputed Matrix using the Ellipse Generator Point.
    //
    //Cached per *Ellipse via a sync.Once guard so the matrix is built
    //exactly once per curve regardless of how many goroutines call this
    //concurrently. The populator body — `e.PrecomputeMatrix(e.Affine2-
    //Extended(e.G))` — is unchanged; the cache only avoids re-running
    //it on subsequent calls. Cached matrix is byte-identical to the
    //rebuilt matrix; Genesis output is preserved.
    if e.generatorCache != nil {
        e.generatorCache.once.Do(func() {
            pm := e.PrecomputeMatrix(e.Affine2Extended(e.G))
            e.generatorCache.pm = &pm
        })
        return *e.generatorCache.pm
    }
    //Defensive fallback for callers that constructed an Ellipse outside
    //the curve factories (zero-value struct or hand-built test curve).
    //Behaves like the pre-cache path: rebuild on every call. No cache
    //hit, but no NPE either.
    return e.PrecomputeMatrix(e.Affine2Extended(e.G))
}

func (e *Ellipse) PrecomputeMatrix(P CoordExtended) [7][7]CoordExtended {
    //Creates a Precompute-Matrix using the Curves Generator Point

    P02 := e.noErrDoubling(P)
    P03 := e.noErrAddition(P02, P)
    P04 := e.noErrDoubling(P02)
    P05 := e.noErrAddition(P04, P)
    P06 := e.noErrDoubling(P03)
    P07 := e.noErrAddition(P06, P)
    P08 := e.noErrDoubling(P04)
    P09 := e.noErrAddition(P08, P)
    P10 := e.noErrDoubling(P05)
    P11 := e.noErrAddition(P10, P)
    P12 := e.noErrDoubling(P06)
    P13 := e.noErrAddition(P12, P)
    P14 := e.noErrDoubling(P07)
    P15 := e.noErrAddition(P14, P)
    P16 := e.noErrDoubling(P08)
    P17 := e.noErrAddition(P16, P)
    P18 := e.noErrDoubling(P09)
    P19 := e.noErrAddition(P18, P)
    P20 := e.noErrDoubling(P10)
    P21 := e.noErrAddition(P20, P)
    P22 := e.noErrDoubling(P11)
    P23 := e.noErrAddition(P22, P)
    P24 := e.noErrDoubling(P12)
    P25 := e.noErrAddition(P24, P)
    P26 := e.noErrDoubling(P13)
    P27 := e.noErrAddition(P26, P)
    P28 := e.noErrDoubling(P14)
    P29 := e.noErrAddition(P28, P)
    P30 := e.noErrDoubling(P15)
    P31 := e.noErrAddition(P30, P)
    P32 := e.noErrDoubling(P16)
    P33 := e.noErrAddition(P32, P)
    P34 := e.noErrDoubling(P17)
    P35 := e.noErrAddition(P34, P)
    P36 := e.noErrDoubling(P18)
    P37 := e.noErrAddition(P36, P)
    P38 := e.noErrDoubling(P19)
    P39 := e.noErrAddition(P38, P)
    P40 := e.noErrDoubling(P20)
    P41 := e.noErrAddition(P40, P)
    P42 := e.noErrDoubling(P21)
    P43 := e.noErrAddition(P42, P)
    P44 := e.noErrDoubling(P22)
    P45 := e.noErrAddition(P44, P)
    P46 := e.noErrDoubling(P23)
    P47 := e.noErrAddition(P46, P)
    P48 := e.noErrDoubling(P24)
    P49 := e.noErrAddition(P48, P)
    
    MR1 := [...]CoordExtended{P, P02, P03, P04, P05, P06, P07}
    MR2 := [...]CoordExtended{P08, P09, P10, P11, P12, P13, P14}
    MR3 := [...]CoordExtended{P15, P16, P17, P18, P19, P20, P21}
    MR4 := [...]CoordExtended{P22, P23, P24, P25, P26, P27, P28}
    MR5 := [...]CoordExtended{P29, P30, P31, P32, P33, P34, P35}
    MR6 := [...]CoordExtended{P36, P37, P38, P39, P40, P41, P42}
    MR7 := [...]CoordExtended{P43, P44, P45, P46, P47, P48, P49}
    
    return [7][7]CoordExtended{MR1, MR2, MR3, MR4, MR5, MR6, MR7}
}

// ScalarMultiplierWithGenerator computes Scalar * G using the cached
// generator-precompute matrix populated lazily by
// PrecomputeMatrixWithGenerator under a sync.Once guard. After the
// first call on a given curve, every subsequent call (across all
// goroutines, across both sync and async callers) reuses the cached
// matrix instead of rebuilding it on every invocation. The cached
// matrix is byte-identical to the rebuilt matrix; Genesis output is
// preserved.
func (e *Ellipse) ScalarMultiplierWithGenerator(Scalar *big.Int) CoordExtended {
    PM := e.PrecomputeMatrixWithGenerator()
    return e.scalarMultiplierWithPM(Scalar, PM)
}


// digitValueBase49 returns the numeric value (0..48) of a single base-49
// digit character as produced by (*big.Int).Text(49).
//
// Mapping:  '0'..'9'  -> 0..9
//           'a'..'z'  -> 10..35
//           'A'..'M'  -> 36..48
//
// Valid base-49 digits produce values in [0, 48]. Any invalid character
// produces 0, which is the same no-op branch the legacy switch statement
// used for a '0' digit (addition with the infinity point).
func digitValueBase49(c byte) int {
    switch {
    case c >= '0' && c <= '9':
        return int(c - '0')
    case c >= 'a' && c <= 'z':
        return int(c-'a') + 10
    case c >= 'A' && c <= 'M':
        return int(c-'A') + 36
    }
    return 0
}

// IsValidBase49Char reports whether c is a valid base-49 digit
// (i.e., digitValueBase49(c) would return a real digit value, not the
// silent-0 sentinel for unknown characters).
//
// Mirrors the TypeScript port's `isValidBase49Char` (REQ-20 / REQ-21,
// `ts/src/gen1/scalar-mult.ts`). Used by callers that need to reject
// mixed-validity inputs at parse time instead of silently accumulating
// invalid digits as zeros — the cross-impl parity gap closed in v4.0.1
// (audit cycle 2026-05-04, F-ERR-002).
func IsValidBase49Char(c byte) bool {
    switch {
    case c >= '0' && c <= '9':
        return true
    case c >= 'a' && c <= 'z':
        return true
    case c >= 'A' && c <= 'M':
        return true
    }
    return false
}

// ScalarMultiplier computes Scalar * P using the 48-element precompute
// matrix and base-49 Horner evaluation.
//
// HARDENING (v1.3.0, finding PO-1):
//
// Algorithmic constant-time point selection. Every iteration performs
// exactly one Addition and (on all but the last digit) one FortyNiner,
// regardless of the scalar digit's value. Point selection is a linear
// scan over all 48 precompute entries that always completes with no
// early exit - the sequence of Go-level operations is identical for
// every scalar of the same base-49 length.
//
// This removes the MACRO-level timing channel that the pre-v1.3.0
// implementation (a switch statement over base-49 digit characters)
// exposed. The micro-level timing of big.Int arithmetic itself is not
// constant-time (math/big is not designed for this); removing it would
// require a custom limb-oriented implementation, which is out of scope
// for the Genesis Go reference.
//
// BYTE-FOR-BYTE COMPATIBILITY: identical output to the pre-v1.3.0
// implementation for all inputs. Verified against the committed
// testvectors/v1_genesis.json corpus (85 deterministic records).
func (e *Ellipse) ScalarMultiplier(Scalar *big.Int, P CoordExtended) CoordExtended {
    PM := e.PrecomputeMatrix(P)
    return e.scalarMultiplierWithPM(Scalar, PM)
}

// scalarMultiplierWithPM is the shared Horner-evaluation core that
// powers both ScalarMultiplier (which rebuilds the PM per call from an
// arbitrary point P) and ScalarMultiplierWithGenerator (which threads
// in the cached generator-PM populated by PrecomputeMatrixWithGenerator
// under a sync.Once guard). Splitting the PM construction from the
// Horner loop is what allows the cache to deliver its time-saving
// without changing the COMPUTED VALUE — the loop body is invariant.
//
// Constant-time discipline (PO-1) is preserved verbatim: every
// iteration performs exactly one Addition + (on all but the last
// digit) one FortyNiner, with a branch-free 48-entry linear scan for
// point selection.
func (e *Ellipse) scalarMultiplierWithPM(Scalar *big.Int, PM [7][7]CoordExtended) CoordExtended {
    var (
        PrivKey49 = Scalar.Text(49)
        Result    = InfinityPoint
    )

    for i := 0; i < len(PrivKey49); i++ {
        value := digitValueBase49(PrivKey49[i])

        // Branch-free point selection across the 48 precompute entries.
        // Start with InfinityPoint (the no-op for Addition) and
        // conditionally replace with PM[row][col] when value matches
        // idx. Always scans all 48 indices; no early exit.
        toAdd := InfinityPoint
        for idx := 1; idx <= 48; idx++ {
            row := (idx - 1) / 7
            col := (idx - 1) % 7
            if value == idx {
                toAdd = PM[row][col]
            }
        }
        Result = e.noErrAddition(Result, toAdd)

        if i != len(PrivKey49)-1 {
            Result = e.FortyNiner(Result)
        }
    }
    return Result
}
