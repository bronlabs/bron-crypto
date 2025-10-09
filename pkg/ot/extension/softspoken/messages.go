package softspoken

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Challenge = [][SigmaBytes]byte // χ_i ∈ [M=η/σ][σ]bits is the random challenge for the consistency check.

// ChallengeResponse (ẋ, ṫ) is the OTe challenge response from the receiver, to be verified by the Sender.
type ChallengeResponse struct {
	X [SigmaBytes]byte        `cbor:"x"`
	T [Kappa][SigmaBytes]byte `cbor:"t"`
}

type Round1P2P struct {
	U                 [Kappa][]byte     `cbor:"u"`                 // [κ][η']bits
	ChallengeResponse ChallengeResponse `cbor:"challengeResponse"` // [σ] + [κ][σ]bits
}

func (r1 *Round1P2P) Validate(xi, l int) error {
	eta := l * xi                       // η = L*ξ
	etaPrimeBytes := eta/8 + SigmaBytes // η'= η + σ
	for i := range Kappa {
		if len(r1.U[i]) != etaPrimeBytes {
			return errs.NewLength("U[%d] length is %d, should be η'=%d", i, len(r1.U[i]), etaPrimeBytes)
		}
	}
	return nil
}
