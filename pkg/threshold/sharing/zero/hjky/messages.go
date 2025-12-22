package hjky

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

// Round1Broadcast carries the Feldman verification vector for the zero-share.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	VerificationVector feldman.VerificationVector[G, S] `cbor:"verificationVector"`
}

// Round1P2P sends the zero-share privately to each participant.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ZeroShare *feldman.Share[S] `cbor:"zeroShare"`
}
