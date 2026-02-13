package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

// Round1Broadcast publishes blinded verification material for the recovery offset.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindVerificationVector feldman.VerificationVector[G, S] `cbor:"blindVerificationVector"`
}

// Round1P2P carries blinded Feldman shares to each party.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindShare *feldman.Share[S] `cbor:"blindShare"`
}

// Round2P2P delivers the aggregated blinded share back to the mislayer.
type Round2P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindedShare       *feldman.Share[S]                `cbor:"blindedShare"`
	VerificationVector feldman.VerificationVector[G, S] `cbor:"verificationVector"`
}
