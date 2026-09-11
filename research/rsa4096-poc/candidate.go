// This file implements STEP 2 of the plan: turning raw bytes pulled off the
// seed stream (stream.go) into an actual numeric candidate worth testing for
// primality. See /.docs/deterministic-rsa4096-from-seed.md §5.2 step 2.
package main

import (
	"errors"
	"io"
	"math/big"
)

// candidateBits / candidateBytes is the target size of one RSA-4096 prime
// factor. RSA-4096 means the modulus n = p*q is 4096 bits, so each of p and
// q must be exactly 2048 bits.
const (
	candidateBits  = 2048
	candidateBytes = candidateBits / 8 // 256
)

// GenerateCandidate pulls exactly one fresh 2048-bit (256-byte) block off
// stream and bit-fixes it into a legitimate primality-test candidate:
//
//   - top bit set to 1        -- guarantees the number is truly 2048 bits,
//     not "2048 bits with leading zeros" (which would silently produce a
//     weaker/smaller-than-advertised key).
//   - second-from-top bit set to 1 -- guarantees that when this prime is
//     multiplied with another prime built the same way, the product
//     reliably lands at exactly 4096 bits. (If only the single top bit were
//     fixed, two "worst case" 2048-bit primes could multiply to a number
//     one bit short of 4096 bits.)
//   - bottom bit set to 1     -- every prime greater than 2 is odd; this
//     guarantees we never waste a draw (and a full trial-division +
//     Miller-Rabin pass) on a guaranteed-composite even number.
//
// These three fixed bits are the only bits NOT coming from the seed stream;
// the remaining 2045 bits are exactly what was read off the tap.
//
// Every call consumes a fresh 256 bytes from stream and never re-reads or
// rewinds -- each candidate is an independent draw, exactly as FIPS 186-5
// and the design doc's "structural, not statistical" correctness bar
// require (every random decision traceable to the one continuous stream).
func GenerateCandidate(stream io.Reader) (*big.Int, error) {
	buf := make([]byte, candidateBytes)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return nil, errors.New("GenerateCandidate: failed to read from seed stream: " + err.Error())
	}

	// Big-endian byte order: buf[0] is the most-significant byte, so its
	// most-significant bits are the "top" of the 2048-bit number.
	buf[0] |= 0b11000000                  // top two bits -> 1
	buf[candidateBytes-1] |= 0b00000001   // bottom bit -> 1

	return new(big.Int).SetBytes(buf), nil
}
