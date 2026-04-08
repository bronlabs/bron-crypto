package hjky

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
)

// Round1Broadcast carries the Feldman verification vector for the zero-share.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	VerificationVector *feldman.VerificationVector[G, S] `cbor:"verificationVector"`
}

func (m *Round1Broadcast[G, S]) Validate(participant *Participant[G, S], _ sharing.ID) error {
	if m == nil || m.VerificationVector == nil {
		return ErrValidationFailed.WithMessage("missing Feldman verification vector")
	}

	r, c := m.VerificationVector.Value().Dimensions()
	if r != int(participant.scheme.MSP().D()) || c != 1 {
		return ErrValidationFailed.WithMessage("invalid Feldman verification vector")
	}
	return nil
}

// Round1P2P sends the zero-share privately to each participant.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ZeroShare *feldman.Share[S] `cbor:"zeroShare"`
}

func (m *Round1P2P[G, S]) Validate(participant *Participant[G, S], _ sharing.ID) error {
	if m == nil || m.ZeroShare == nil {
		return ErrValidationFailed.WithMessage("missing zero share")
	}
	if m.ZeroShare.ID() != participant.SharingID() {
		return ErrValidationFailed.WithMessage("zero share ID does not match recipient ID")
	}
	return nil
}
