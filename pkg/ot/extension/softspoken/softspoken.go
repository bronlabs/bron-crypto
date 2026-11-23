package softspoken

import "github.com/bronlabs/bron-crypto/pkg/ot"

// Message is the type of the output messages: κ = 128 bits, which fixes the
// number of base OTs and the row width as well.
type Message = ot.Message128

const (
	// protocolDomainSeparator is appended to the session transcript when a
	// participant is created, after the IKNP03 one.
	protocolDomainSeparator = "BRON_CRYPTO-SOFTSPOKEN-"
	// chiLabel labels the extraction of the Fiat–Shamir challenge χ.
	chiLabel = "BRON_CRYPTO-SOFTSPOKEN-CHALLENGE"
	// responseLabel labels the receiver's check responses x̄, t̄¹..t̄^κ, which
	// both parties append to the transcript.
	responseLabel = "BRON_CRYPTO-SOFTSPOKEN-RESPONSE-"
	// sigma is the security parameter s of Figure 10 raised to κ as DKLs23
	// Section 5.1 requires under Fiat–Shamir: the check works over
	// F_{2^sigma} and every extension costs sigma extra OTs. It is also the
	// block size of the check, so ℓ must be a multiple of it.
	sigma = 128
	// sigmaBytes is sigma in bytes.
	sigmaBytes = sigma / 8
)
