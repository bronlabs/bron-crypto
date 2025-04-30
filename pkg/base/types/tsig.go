package types

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type ThresholdSignatureParticipant[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] interface {
	ThresholdParticipant[P, F, S]
	Quorum() ds.Set[IdentityKey[P, F, S]]
}

type ThresholdSignatureProtocol[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] interface {
	ThresholdProtocol[C, P, F, S]
	SigningSuite() SigningSuite[C, P, F, S]
}

func NewThresholdSignatureProtocol[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](signingSuite SigningSuite[C, P, F, S], participants ds.Set[IdentityKey[P, F, S]], threshold uint) (ThresholdSignatureProtocol[C, P, F, S], error) {
	protocol := &protocol[C, P, F, S]{
		curve:        signingSuite.Curve(),
		hash:         signingSuite.Hash(),
		participants: participants,
		threshold:    threshold,
	}

	return protocol, nil
}
