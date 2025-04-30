package types

import (
	"encoding/binary"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type SharingID uint

func SharingIDToScalar[S fields.PrimeFieldElement[S]](id SharingID, scalarField fields.PrimeField[S]) S {
	// TODO: change to FromUint64
	idBytes := binary.BigEndian.AppendUint64(nil, uint64(id))
	s, _ := scalarField.FromWideBytes(idBytes)
	return s
}

type SharingConfig[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] AbstractIdentitySpace[SharingID, P, F, S]

type ThresholdParticipant[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] interface {
	Participant[P, F, S]
	SharingId() SharingID
}

type ThresholdProtocol[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] interface {
	Protocol[C, P, F, S]
	Threshold() uint
	TotalParties() uint
}

func NewThresholdProtocol[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](curve C, participants ds.Set[IdentityKey[P, F, S]], threshold uint) (ThresholdProtocol[C, P, F, S], error) {
	protocol := &protocol[C, P, F, S]{
		curve:        curve,
		participants: participants,
		threshold:    threshold,
	}

	return protocol, nil
}

func DeriveSharingConfig[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](identityKeys ds.Set[IdentityKey[P, F, S]]) SharingConfig[P, F, S] {
	return NewAbstractIdentitySpace[SharingID, P, F, S](identityKeys)
}
