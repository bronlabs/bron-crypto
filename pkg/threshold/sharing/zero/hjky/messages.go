package hjky

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	VerificationVector feldman.VerificationVector[G, S] `cbor:"verificationVector"`
}

type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ZeroShare *feldman.Share[S] `cbor:"zeroShare"`
}
