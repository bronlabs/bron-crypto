package types

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type protocol[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	curve        C
	hash         func() hash.Hash
	participants ds.Set[IdentityKey[P, F, S]]
	threshold    uint
}

func (p *protocol[C, P, F, S]) Curve() C {
	return p.curve
}

func (p *protocol[C, P, F, S]) Clone() Protocol[C, P, F, S] {
	var clonedParticipants ds.Set[IdentityKey[P, F, S]]
	if p.participants != nil {
		clonedParticipants = p.participants.Clone()
	}

	return &protocol[C, P, F, S]{
		curve:        p.curve,
		hash:         p.hash,
		participants: clonedParticipants,
		threshold:    p.threshold,
	}
}

func (p *protocol[C, P, F, S]) Hash() func() hash.Hash {
	return p.hash
}

func (p *protocol[C, P, F, S]) Participants() ds.Set[IdentityKey[P, F, S]] {
	return p.participants
}

func (p *protocol[C, P, F, S]) Threshold() uint {
	return p.threshold
}

func (p *protocol[C, P, F, S]) TotalParties() uint {
	return uint(p.participants.Size())
}

func (p *protocol[C, P, F, S]) SigningSuite() SigningSuite[C, P, F, S] {
	return p
}

func (*protocol[C, P, F, S]) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}
