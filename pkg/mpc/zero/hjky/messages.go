package hjky

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
)

// Round1Broadcast carries the Feldman verification vector for the zero-share.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	VerificationVector feldman.VerificationVector[G, S] `cbor:"verificationVector"`
}

func (m *Round1Broadcast[G, S]) Validate(participant *Participant[G, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing message")
	}
	if m.VerificationVector == nil {
		return ErrValidation.WithMessage("missing Feldman verification vector")
	}
	if m.VerificationVector.Degree()+1 != int(participant.accessStructure.Threshold()) {
		return ErrValidation.WithMessage("invalid Feldman verification vector degree: %d", m.VerificationVector.Degree())
	}
	coeffs := m.VerificationVector.Coefficients()
	if len(coeffs) != int(participant.accessStructure.Threshold()) {
		return ErrValidation.WithMessage("invalid Feldman verification vector size")
	}
	for i, coeff := range coeffs {
		if utils.IsNil(coeff) {
			return ErrValidation.WithMessage("missing Feldman verification vector coefficient %d", i)
		}
	}
	return nil
}

// Round1P2P sends the zero-share privately to each participant.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ZeroShare *feldman.Share[S] `cbor:"zeroShare"`
}

func (m *Round1P2P[G, S]) Validate(participant *Participant[G, S], _ sharing.ID) error {
	if m.ZeroShare == nil {
		return ErrValidation.WithMessage("missing zero share")
	}
	if m.ZeroShare.ID() != participant.SharingID() {
		return ErrValidation.WithMessage("zero share ID does not match recipient ID")
	}
	return nil
}
