package softspoken

import (
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// Challenge is the verifier's random challenge for the consistency check (χ_i ∈ [M=η/σ][σ] bits).
type Challenge = [][SigmaBytes]byte // χ_i ∈ [M=η/σ][σ]bits is the random challenge for the consistency check.

// ChallengeResponse (ẋ, ṫ) is the OTe challenge response from the receiver, to be verified by the Sender.
type ChallengeResponse struct {
	X [SigmaBytes]byte        `cbor:"x"`
	T [Kappa][SigmaBytes]byte `cbor:"t"`
}

// Round1P2P carries masked payloads and the Fiat-Shamir challenge response.
type Round1P2P struct {
	U                 [Kappa][]byte     `cbor:"u"`                 // [κ][η']bits
	ChallengeResponse ChallengeResponse `cbor:"challengeResponse"` // [σ] + [κ][σ]bits
}

// Validate checks lengths of U entries against suite parameters.
func (r1 *Round1P2P) Validate(xi, l int) error {
	eta := l * xi                       // η = L*ξ
	etaPrimeBytes := eta/8 + SigmaBytes // η'= η + σ
	for i := range Kappa {
		if len(r1.U[i]) != etaPrimeBytes {
			return ot.ErrInvalidArgument.WithMessage("U[%d] length is %d, should be η'=%d", i, len(r1.U[i]), etaPrimeBytes)
		}
	}
	return nil
}
