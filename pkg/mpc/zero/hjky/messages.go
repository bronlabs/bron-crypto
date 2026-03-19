package hjky

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1Broadcast carries the Feldman verification vector for the zero-share.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	VerificationVector feldman.VerificationVector[G, S] `cbor:"verificationVector"`
}

func (m *Round1Broadcast[G, S]) Validate(participant *Participant[G, S]) error {
	if m.VerificationVector == nil {
		return network.ErrInvalidMessage.WithMessage("missing Feldman verification vector")
	}
	if m.VerificationVector.Degree()+1 != int(participant.accessStructure.Threshold()) {
		return network.ErrInvalidMessage.WithMessage("invalid Feldman verification vector degree: %d", m.VerificationVector.Degree())
	}
	return nil
}

// Round1P2P sends the zero-share privately to each participant.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ZeroShare *feldman.Share[S] `cbor:"zeroShare"`
}

func (m *Round1P2P[G, S]) Validate(participant *Participant[G, S]) error {
	if m.ZeroShare == nil {
		return network.ErrInvalidMessage.WithMessage("missing zero share")
	}
	if m.ZeroShare.ID() != participant.SharingID() {
		return network.ErrInvalidMessage.WithMessage("zero share ID does not match recipient ID")
	}
	return nil
}
