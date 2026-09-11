package main

import (
    el "DALOS_Crypto/Elliptic"
    "DALOS_Crypto/keystore"
    "flag"
    "fmt"
    "log"
    "os"
)

// Function to confirm seed words
// confirmSeedWords prompts the user to retype the seed words for confirmation.
// Returns nil on successful match; returns a wrapped error on read failure,
// count mismatch, or per-word mismatch.
//
// F-MED-006 (audit cycle 2026-05-04, v4.0.2): refactored from process-
// terminating (`os.Exit(1)` from inside the helper) to sentinel-return
// per the Phase 10 / REQ-31 / v4.0.0 convention. Caller in main() now
// owns the os.Exit decision. This makes the helper testable in
// isolation (mock stdin via os.Pipe) and consistent with sibling
// helpers in process.go that already follow the sentinel pattern.
func confirmSeedWords(seedWords []string) error {
    fmt.Println("Please retype the seed words to confirm (separated by spaces):")

    inputWords := make([]string, 0, len(seedWords))

    // Using fmt.Scan to read all words (space-separated) into inputWords.
    // F-LOW-015 (audit cycle 2026-05-04, v4.0.3): the post-loop length
    // check that used to follow this loop has been removed — it was dead
    // code. The loop runs exactly len(seedWords) iterations; on any
    // fmt.Scan failure the early `return` above fires, so reaching the
    // statement after the loop guarantees `len(inputWords) ==
    // len(seedWords)`. The deleted check could never observe a mismatch
    // and was pure noise. Per-word equality check below is the actual
    // confirmation gate.
    for i := 0; i < len(seedWords); i++ {
        var word string
        _, err := fmt.Scan(&word)
        if err != nil {
            return fmt.Errorf("reading input word %d: %w", i+1, err)
        }
        inputWords = append(inputWords, word)
    }

    // Check each seed word
    for i, word := range seedWords {
        if word != inputWords[i] {
            return fmt.Errorf("seed word %d (%q) does not match %q", i+1, word, inputWords[i])
        }
    }

    fmt.Println("Seed words confirmed successfully.")
    return nil
}

func main() {
    // Variables
    DalosEllipse := el.DalosEllipse()

    // Main command flags
    generateFlag := flag.Bool("g", false, "Generate a DALOS Key-Pair")
    specialGenerateFlag := flag.Bool("gd", false, "Special variant of generating a DALOS Key-Pair in Demo Mode (must be used alone)")
    convertFlag := flag.Bool("c", false, "Convert a DALOS PRIV Key to a PUBL Key")
    
    openFlag := flag.String("open", "", "Path to the wallet file to open")
    signFlag := flag.String("sign", "", "Signs a message with the private Key from the Opened Walelt")
    verifyFlag := flag.String("verify", "", "Verifies the signature of a Message m against a public key")
    
    // Sub-options for generating
    rawFlag := flag.Bool("raw", false, "Generate a DALOS KEY-Pair from random bits")
    bitFlag := flag.String("bits", "", "Generate a DALOS KEY-Pair from specific bits")
    seedFlag := flag.Int("seed", 0, "Generate a DALOS KEY-Pair from a Seed Words (specify number of words)")
    safeFlag := flag.Bool("safe", false, "Require confirmation of seed words")
    intaFlag := flag.String("i10", "", "Generate a DALOS KEY-Pair from an integer in base 10 as string")
    intbFlag := flag.String("i49", "", "Generate a DALOS KEY-Pair from an integer in base 49 as string")
    
    // Sub-options for generating an account
    smartFlag := flag.Bool("smart", false, "Generates a Smart DALOS Account")
    
    // Password flag for encryption.
    //
    // F-MED-002 (audit cycle 2026-05-04, v4.0.2): the `-p PASSWORD` form
    // leaks via shell history, /proc/PID/cmdline, `ps -ef`, auditd, and
    // container logs. The proper fix is interactive `term.ReadPassword`
    // — but that requires `golang.org/x/term` which would break this
    // package's "no external deps" invariant (see CLAUDE.md "Two
    // implementations, one contract" → "no external deps" + go.mod
    // F-MED-003 docstring). The CLI is documented
    // as a developer convenience, NOT for production wallet management
    // (production consumers use OuronetUI which has its own secure
    // input pipeline). Scope-decision: keep `-p` as the only password
    // input mechanism; document the limitation.
    //
    // F-MED-004 (audit cycle 2026-05-04, v4.0.2): added 16-character
    // minimum length validation. Combined with the documented AES-2
    // single-pass-Blake3 KDF (no salt, no iterations), passwords below
    // ~12 chars are GPU-brute-forceable in days. 16 chars at ~70-char
    // alphabet gives ~3.3e29 combinations → safe against any realistic
    // attacker even without KDF strengthening. Note: this validation
    // is only applied when generating new wallets (-g flag); decrypt
    // operations (-open, -sign) accept any-length password since the
    // user is recovering an existing wallet that may predate this rule.
    passwordFlag := flag.String("p", "", "Password to encrypt or decrypt the private key (required for key generation; min 16 chars; visible in shell history — for production keys use OuronetUI)")
    // Message flag containing the Message to be signed or verified
    messageFlag := flag.String("m", "", "Contains the Message to be signed or verified")
    // Public flag containing a Public Key to be used for signature verification
    publicFlag := flag.String("public", "", "Contains the Public Key to be used for verifying a Signature of a Message")
    
    // Sub-options for conversion
    bitConvFlag := flag.String("bs", "", "Converts a private Key as BitString to Public Key")
    intConvFlag := flag.String("int10", "", "Converts a private Key as String representing an Integer in Base 10 to Public Key")
    // F-LOW-003 (audit cycle 2026-05-04, v4.0.3): the "-int49" flag's
    // help-text used to read "...Integer in Base 10..." — copy-paste
    // mismatch with the flag name. Users reading `dalos -h` saw both
    // -int10 and -int49 described as "Base 10". Fixed to "Base 49".
    strConvFlag := flag.String("int49", "", "Converts a private Key as String representing an Integer in Base 49 to Public Key")
    
    // Parse the flags
    flag.Parse()
    
    // Check if -safe is used without -seed
    if *safeFlag && *seedFlag == 0 {
        fmt.Println("Error: The -safe flag can only be used with the -seed flag.")
        os.Exit(1)
    }
    
    // Ensure `-gd` (special generate) is used alone
    if *specialGenerateFlag {
        if flag.NFlag() > 1 {
            fmt.Println("Error: -gd must be used alone with no other flags.")
            os.Exit(1)
        }
        fmt.Println("Generating a DALOS Key-Pair with special variant...")
        // Handle special generation logic here
        RandomBits := DalosEllipse.GenerateRandomBitsOnCurve()
        ProcessPrivateKeyConversion(&DalosEllipse, RandomBits)
        os.Exit(0) // Exit after special generation
    }
    // Ensure that if -g is used, we also have the required flags
    if *generateFlag {
        // Validate the presence of one of the key generation methods (-raw, -bits, -seed, -i10, -i49)
        if !*rawFlag && *bitFlag == "" && *seedFlag == 0 && *intaFlag == "" && *intbFlag == "" {
            fmt.Println("Error: One of -raw, -bits, -seed, -i10, or -i49 must be provided when using -g.")
            os.Exit(1)
        }
        // F-MED-001 (audit cycle 2026-05-04, v4.0.2): reject mutually-exclusive
        // input-method combinations BEFORE dispatch. Pre-fix, multiple input
        // flags (e.g. `-g -raw -bits 0101...`) executed both branches as
        // separate `if` statements, generating + printing + attempting to save
        // TWO unrelated wallets in a single invocation. Now exactly ONE input
        // method must be selected; the dispatch below uses else-if for
        // defense-in-depth.
        inputMethodCount := 0
        if *rawFlag {
            inputMethodCount++
        }
        if *bitFlag != "" {
            inputMethodCount++
        }
        if *seedFlag > 0 {
            inputMethodCount++
        }
        if *intaFlag != "" {
            inputMethodCount++
        }
        if *intbFlag != "" {
            inputMethodCount++
        }
        if inputMethodCount > 1 {
            fmt.Println("Error: -raw, -bits, -seed, -i10, and -i49 are mutually exclusive — pick exactly one input method per invocation.")
            os.Exit(1)
        }
        // Validate that the -p (password) flag is provided
        if *passwordFlag == "" {
            fmt.Println("Error: -p (password) flag is required when using -g Flag.")
            os.Exit(1)
        }
        // F-MED-004 (v4.0.2): minimum password-strength validation. See
        // the passwordFlag declaration block above for the full rationale
        // (AES-2 single-pass-Blake3 KDF + GPU-brute-force resistance math).
        const minPasswordChars = 16
        if len(*passwordFlag) < minPasswordChars {
            fmt.Fprintf(os.Stderr,
                "Error: -p password must be at least %d characters long (got %d). "+
                    "DALOS uses single-pass Blake3 KDF without salt; weak passwords are GPU-brute-forceable.\n",
                minPasswordChars, len(*passwordFlag))
            os.Exit(1)
        }
        // F-MED-001 (v4.0.2): converted to else-if dispatch so a future
        // contributor adding a 6th input method doesn't accidentally
        // re-introduce the multi-fire bug.
        // Proceed with the key generation logic -raw Flag
        if *rawFlag {
            fmt.Println("Generating Key-Pair from random bits...")
            RandomBits := DalosEllipse.GenerateRandomBitsOnCurve()
            ProcessKeyGeneration(&DalosEllipse, RandomBits, smartFlag, *passwordFlag)
        // If -seed is used, validate that the correct number of seed words are provided
        } else if *seedFlag > 0 {
            seedCount := *seedFlag
            seedWords := flag.Args()
            // Validate seed word COUNT against the -seed N flag itself
            // (a CLI-only convenience check: the caller must state up
            // front how many words follow, and that count must match
            // what was actually typed).
            if len(seedWords) != seedCount {
                fmt.Printf("Error: Expected %d words, but got %d.\n", seedCount, len(seedWords))
                os.Exit(1)
            }
            // Final restriction level (settled 2026-09-11): the ONE
            // seed-word contract, enforced identically everywhere in the
            // codebase (this CLI, the Go library, the TS port) via
            // Elliptic.ValidateSeedWords — 1-256 words, each 1-256
            // glyphs, every glyph one of the 256 in the DALOS
            // CharacterMatrix. This CLI used to run its own separate,
            // inconsistent checks (a stricter 4-256 word-count floor,
            // and a byte-length check that silently miscounted
            // multi-byte UTF-8 glyphs) — replaced here so there is
            // exactly one place this contract is defined.
            // See Elliptic/SeedWordsValidation.go.
            if err := el.ValidateSeedWords(seedWords); err != nil {
                fmt.Println("Error:", err)
                os.Exit(1)
            }
            fmt.Println("Seed Words are valid. Proceeding with Key-Pair generation from Seed Words.")
            // Seed words confirmation if -safe flag is used.
            // F-MED-006 (v4.0.2): confirmSeedWords now returns error;
            // CLI driver owns the os.Exit decision.
            if *safeFlag {
                if err := confirmSeedWords(seedWords); err != nil {
                    fmt.Fprintln(os.Stderr, "Error:", err)
                    os.Exit(1)
                }
            }
            // Call the key generation logic using the valid seed words
            BitString, err := DalosEllipse.SeedWordsToBitString(seedWords)
            if err != nil {
                fmt.Println("Error:", err)
                os.Exit(1)
            }
            ProcessKeyGeneration(&DalosEllipse, BitString, smartFlag, *passwordFlag)
        // Handle other generation methods (e.g., -bits, -i10, -i49) here...
        // Proceed with the key generation logic -bits Flag
        } else if *bitFlag != "" {
            fmt.Println("Generating Key-Pair from specific bits...")
            // Validate the provided bit string using the ValidateBitString function
            TotalBoolean, LengthBoolean, StructureBoolean := DalosEllipse.ValidateBitString(*bitFlag)
            
            // Check validation results and provide detailed error messages
            if !TotalBoolean {
                if !LengthBoolean {
                    fmt.Println("Error: The provided bit string has an incorrect length.")
                }
                if !StructureBoolean {
                    fmt.Println("Error: The provided bit string contains invalid characters (only '0' and '1' are allowed).")
                }
                os.Exit(1)
            }
            
            // Proceed with processing the bit string since validation passed
            BitString := *bitFlag
            ProcessKeyGeneration(&DalosEllipse, BitString, smartFlag, *passwordFlag)
        } else if *intaFlag != "" {
            fmt.Println("Generating key pair from string representing an integer in base 10...")
            BitString := ProcessIntegerFlag(&DalosEllipse, *intaFlag, true)
            if BitString == "" {
                fmt.Println("Aborting -i10 base-10 key generation.")
                os.Exit(1)
            }
            ProcessKeyGeneration(&DalosEllipse, BitString, smartFlag, *passwordFlag)
        } else if *intbFlag != "" {
            fmt.Println("Generating key pair from string representing an integer in base 49...")
            BitString := ProcessIntegerFlag(&DalosEllipse, *intbFlag, false)
            if BitString == "" {
                fmt.Println("Aborting -i49 base-49 key generation.")
                os.Exit(1)
            }
            ProcessKeyGeneration(&DalosEllipse, BitString, smartFlag, *passwordFlag)
        }

    } else if *convertFlag {
        // Handle the key conversion cases
        if *bitConvFlag != "" {
            fmt.Println("Converting The BitString to Public key and Dalos Accounts...")
            BitString := *bitConvFlag
            ProcessPrivateKeyConversion(&DalosEllipse, BitString)
        } else if *intConvFlag != "" {
            fmt.Println("Converting The String Representing an Integer in base 10 to Public key and Dalos Accounts...")
            BitString := ProcessIntegerFlag(&DalosEllipse, *intConvFlag, true)
            if BitString == "" {
                fmt.Println("Aborting -int10 base-10 conversion.")
                os.Exit(1)
            }
            ProcessPrivateKeyConversion(&DalosEllipse, BitString)
        } else if *strConvFlag != "" {
            fmt.Println("Converting The String Representing an Integer in base 49 to Public key and Dalos Accounts...")
            BitString := ProcessIntegerFlag(&DalosEllipse, *strConvFlag, false)
            if BitString == "" {
                fmt.Println("Aborting -int49 base-49 conversion.")
                os.Exit(1)
            }
            ProcessPrivateKeyConversion(&DalosEllipse, BitString)
        } else {
            fmt.Println("Error: No valid conversion method selected.")
            flag.Usage()
            os.Exit(1)
        }
    } else if *openFlag != "" {
        // Check if the password flag is also set
        if *passwordFlag == "" {
            fmt.Println("Error: -p (password) flag is required when using -open Flag.")
            os.Exit(1)
        }
        
        // F-MED-009 (v4.0.2): breadcrumb prints relocated from
        // keystore.ImportPrivateKey (library purity restored). CLI
        // owns chrome; library returns data.
        fmt.Println("DALOS Keys are being opened!")
        ReadKeyPair, err := keystore.ImportPrivateKey(&DalosEllipse, *openFlag, *passwordFlag)
        if err != nil {
            log.Fatalf("Error opening wallet: %v", err)
        }
        fmt.Println("Public Key verification successful!")

        //Print the Private Key on Screen
        BitString := ProcessIntegerFlag(&DalosEllipse, ReadKeyPair.PRIV, false)
        if BitString == "" {
            fmt.Println("Aborting wallet open: private key invalid.")
            os.Exit(1)
        }
        ProcessPrivateKeyConversion(&DalosEllipse, BitString)
    } else if *signFlag != "" {
        // Check if the password flag is also set
        if *passwordFlag == "" {
            fmt.Println("Error: -p (password) flag is required when using -sign Flag.")
            os.Exit(1)
        }
        if *messageFlag == "" {
            fmt.Println("Error: -m (message) flag is required when using -sign Flag.")
            os.Exit(1)
        }
        
        // F-MED-009 (v4.0.2): breadcrumb prints relocated from
        // keystore.ImportPrivateKey (library purity restored). CLI
        // owns chrome; library returns data.
        fmt.Println("DALOS Keys are being opened!")
        ReadKeyPair, err := keystore.ImportPrivateKey(&DalosEllipse, *signFlag, *passwordFlag)
        if err != nil {
            log.Fatalf("Error opening wallet: %v", err)
        }
        fmt.Println("Public Key verification successful!")

        //Print the Signature on screen
        // F-API-005 (v4.0.1): SchnorrSign returns (string, error) instead
        // of silently returning "" on internal failure. CLI behaviour:
        // print to stderr + os.Exit(1) so a pipe consumer doesn't get an
        // empty signature blob with no diagnostic.
        Signature, err := DalosEllipse.SchnorrSign(ReadKeyPair, *messageFlag)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Error: signing failed:", err)
            os.Exit(1)
        }
        fmt.Println("Your Signature is:")
        fmt.Println("")
        fmt.Println(Signature)
        fmt.Println("")
    } else if *verifyFlag != "" {
        // Check if the password flag is also set
        
        if *messageFlag == "" {
            fmt.Println("Error: -m (message) flag is required when using -verify Flag.")
            os.Exit(1)
        }
        if *publicFlag == "" {
            fmt.Println("Error: -public (Public-Key Input) flag is required when using -verify Flag.")
            os.Exit(1)
        }
        
        //Verify the Signature and print Verification on screen
        Verification := DalosEllipse.SchnorrVerify(*verifyFlag, *messageFlag, *publicFlag)
        fmt.Println("")
        fmt.Println("Your Verification is:")
        fmt.Println("")
        fmt.Println(Verification)
        fmt.Println("")
    } else {
        fmt.Println("Error: No valid operation selected.")
        flag.Usage()
        os.Exit(1)
    }
}
