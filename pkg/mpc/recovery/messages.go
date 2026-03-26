package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
)

// Round1Broadcast publishes blinded verification material for the recovery offset.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindVerificationVector feldman.VerificationVector[G, S] `cbor:"blindVerificationVector"`
}

func (m *Round1Broadcast[G, S]) Validate(p *Recoverer[G, S], _ sharing.ID) error {
	if m == nil || m.BlindVerificationVector == nil {
		return ErrValidation.WithMessage("missing fields in Round1Broadcast message")
	}
	if m.BlindVerificationVector.Degree() != int(p.scheme.AccessStructure().Threshold())-1 {
		return ErrValidation.WithMessage("invalid message")
	}

	return nil
}

// Round1P2P carries blinded Feldman shares to each party.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindShare *feldman.Share[S] `cbor:"blindShare"`
}

func (m *Round1P2P[G, S]) Validate(*Recoverer[G, S], sharing.ID) error {
	if m == nil || m.BlindShare == nil {
		return ErrValidation.WithMessage("missing fields in Round1P2P message")
	}

	return nil
}

// Round2P2P delivers the aggregated blinded share back to the mislayer.
type Round2P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	BlindedShare       *feldman.Share[S]                `cbor:"blindedShare"`
	VerificationVector feldman.VerificationVector[G, S] `cbor:"verificationVector"`
}

func (m *Round2P2P[G, S]) Validate(p *Mislayer[G, S], _ sharing.ID) error {
	if m == nil || m.BlindedShare == nil || m.VerificationVector == nil {
		return ErrValidation.WithMessage("missing fields in Round2P2P message")
	}
	if m.VerificationVector.Degree() != int(p.scheme.AccessStructure().Threshold())-1 {
		return ErrValidation.WithMessage("invalid message")
	}

	return nil
}
