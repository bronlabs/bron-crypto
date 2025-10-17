package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindVerificationVector feldman.VerificationVector[G, S] `cbor:"blindVerificationVector"`
}

type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindShare *feldman.Share[S] `cbor:"blindShare"`
}

type Round2Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	VerificationVector feldman.VerificationVector[G, S] `cbor:"verificationVector"`
}

type Round2P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindedShare *feldman.Share[S] `cbor:"blindedShare"`
}
