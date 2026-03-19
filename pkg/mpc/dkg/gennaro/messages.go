package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1Broadcast carries the dealer’s Pedersen VSS verification vector.
type Round1Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	PedersenVerificationVector pedersenVSS.VerificationVector[E, S] `cbor:"verificationVector"`
	Proof                      compiler.NIZKPoKProof                `cbor:"proof"`
}

func (m *Round1Broadcast[E, S]) Validate(participant *Participant[E, S]) error {
	if m.PedersenVerificationVector == nil {
		return network.ErrInvalidMessage.WithMessage("missing Pedersen verification vector")
	}
	if m.PedersenVerificationVector.Degree()+1 != int(participant.ac.Threshold()) {
		return network.ErrInvalidMessage.WithMessage("invalid Pedersen verification vector degree")
	}
	if len(m.Proof) == 0 {
		return network.ErrInvalidMessage.WithMessage("missing proof of well-formedness")
	}
	return nil
}

// Round1Unicast carries the dealer’s Pedersen share to a specific party.
type Round1Unicast[E GroupElement[E, S], S Scalar[S]] struct {
	Share *pedersenVSS.Share[S] `cbor:"share"`
}

func (m *Round1Unicast[E, S]) Validate(participant *Participant[E, S]) error {
	if m.Share == nil {
		return network.ErrInvalidMessage.WithMessage("missing Pedersen share")
	}
	if m.Share.ID() != participant.SharingID() {
		return network.ErrInvalidMessage.WithMessage("Pedersen share ID does not match recipient ID")
	}
	return nil
}

// Round2Broadcast carries the Feldman VSS verification vector and proof of well-formedness.
type Round2Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	FeldmanVerificationVector feldman.VerificationVector[E, S] `cbor:"verificationVector"`
	Proof                     compiler.NIZKPoKProof            `cbor:"proof"`
}

func (m *Round2Broadcast[E, S]) Validate(*Participant[E, S]) error {
	if m.FeldmanVerificationVector == nil {
		return network.ErrInvalidMessage.WithMessage("missing Feldman verification vector")
	}
	if m.FeldmanVerificationVector.Degree()+1 != int(m.FeldmanVerificationVector.Degree()+1) {
		return network.ErrInvalidMessage.WithMessage("invalid Feldman verification vector degree")
	}
	if len(m.Proof) == 0 {
		return network.ErrInvalidMessage.WithMessage("missing proof of well-formedness")
	}
	return nil
}
