package types

import (
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
)

type protocol struct {
	curve        curves.Curve
	hash         func() hash.Hash
	participants ds.Set[IdentityKey]
	threshold    uint
	flags        ds.Set[ValidationFlag]
}

func (p *protocol) Curve() curves.Curve {
	return p.curve
}

func (p *protocol) Clone() Protocol {
	var clonedFlags ds.Set[ValidationFlag]
	if p.flags != nil {
		clonedFlags = p.flags.Clone()
	}
	var clonedParticipants ds.Set[IdentityKey]
	if p.participants != nil {
		clonedParticipants = p.participants.Clone()
	}
	return &protocol{
		curve:        p.curve,
		hash:         p.hash,
		participants: clonedParticipants,
		threshold:    p.threshold,
		flags:        clonedFlags,
	}
}

func (p *protocol) Hash() func() hash.Hash {
	return p.hash
}

func (p *protocol) Participants() ds.Set[IdentityKey] {
	return p.participants
}

func (p *protocol) Threshold() uint {
	return p.threshold
}

func (p *protocol) TotalParties() uint {
	return safecast.ToUint(p.participants.Size())
}

func (p *protocol) SigningSuite() SigningSuite {
	return p
}

func (*protocol) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

func (p *protocol) Flags() ds.Set[ValidationFlag] {
	return p.flags
}
