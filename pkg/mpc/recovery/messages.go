package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
)

// Round1Broadcast publishes blinded verification material for the recovery offset.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindVerificationVector feldman.VerificationVector[G, S] `cbor:"blindVerificationVector"`
}

func (*Round1Broadcast[G, S]) Validate(recoverer *Recoverer[G, S]) error { return nil }

// Round1P2P carries blinded Feldman shares to each party.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindShare *feldman.Share[S] `cbor:"blindShare"`
}

func (*Round1P2P[G, S]) Validate(recoverer *Recoverer[G, S]) error { return nil }

// Round2P2P delivers the aggregated blinded share back to the mislayer.
type Round2P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindedShare       *feldman.Share[S]                `cbor:"blindedShare"`
	VerificationVector feldman.VerificationVector[G, S] `cbor:"verificationVector"`
}

func (*Round2P2P[G, S]) Validate(mislayer *Mislayer[G, S]) error { return nil }
