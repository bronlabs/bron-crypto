package types

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type Participant[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] interface {
	IdentityKey() IdentityKey[P, F, S]
}

type Protocol[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] interface {
	Curve() C // Most supported protocols are algebraic.
	Participants() ds.Set[IdentityKey[P, F, S]]
	Clone() Protocol[C, P, F, S]
}

func NewProtocol[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](curve C, participants ds.Set[IdentityKey[P, F, S]]) (Protocol[C, P, F, S], error) {
	protocol := &protocol[C, P, F, S]{
		curve:        curve,
		participants: participants,
	}

	return protocol, nil
}
