package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1Broadcast carries the dealer’s Pedersen VSS verification vector.
type Round1Broadcast[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	PedersenVerificationVector *pedersenVSS.VerificationVector[E, S] `cbor:"verificationVector"`
	Proof                      compiler.NIZKPoKProof                 `cbor:"proof"`
}

func (m *Round1Broadcast[E, S]) Validate(participant *Participant[E, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round1Broadcast message")
	}
	if m.PedersenVerificationVector == nil {
		return ErrValidation.WithMessage("missing Pedersen verification vector")
	}
	rows, cols := m.PedersenVerificationVector.Value().Dimensions()
	if cols != 1 {
		return ErrValidation.WithMessage("pedersen verification vector is not a column vector")
	}
	if rows != int(participant.state.lsss.MSP().D()) {
		return ErrValidation.WithMessage("invalid Pedersen verification vector size")
	}
	if len(m.Proof) == 0 {
		return ErrValidation.WithMessage("missing okamoto proof")
	}

	return nil
}

// Round1Unicast carries the dealer’s Pedersen share to a specific party.
type Round1Unicast[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	Share *pedersenVSS.Share[S] `cbor:"share"`
}

func (m *Round1Unicast[E, S]) Validate(participant *Participant[E, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round1Unicast message")
	}
	if m.Share == nil {
		return ErrValidation.WithMessage("missing Pedersen share")
	}
	if m.Share.ID() != participant.SharingID() {
		return ErrValidation.WithMessage("Pedersen share ID does not match recipient ID")
	}
	return nil
}

// Round2Broadcast carries the Feldman VSS verification vector and proof of well-formedness.
type Round2Broadcast[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	FeldmanVerificationVector *feldman.VerificationVector[E, S] `cbor:"verificationVector"`
	Proof                     compiler.NIZKPoKProof             `cbor:"proof"`
}

func (m *Round2Broadcast[E, S]) Validate(participant *Participant[E, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round2Broadcast message")
	}
	if m.FeldmanVerificationVector == nil {
		return ErrValidation.WithMessage("missing Feldman verification vector")
	}
	rows, cols := m.FeldmanVerificationVector.Value().Dimensions()
	if cols != 1 {
		return ErrValidation.WithMessage("feldman verification vector is not a column vector")
	}
	if rows != int(participant.state.lsss.MSP().D()) {
		return ErrValidation.WithMessage("invalid Feldman verification vector size")
	}
	if len(m.Proof) == 0 {
		return ErrValidation.WithMessage("missing batch dlog proof")
	}
	return nil
}
