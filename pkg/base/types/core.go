package types

import (
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

type cipherSuite struct {
	curve curves.Curve
	hash  func() hash.Hash

	_ ds.Incomparable
}

func (cs *cipherSuite) Curve() curves.Curve {
	return cs.curve
}

func (cs *cipherSuite) Hash() func() hash.Hash {
	return cs.hash
}

func (*cipherSuite) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

type protocol struct {
	curve        curves.Curve
	hash         func() hash.Hash
	participants ds.Set[IdentityKey]
	threshold    uint
}

func (p *protocol) Curve() curves.Curve {
	return p.curve
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
	return uint(p.participants.Size())
}

func (p *protocol) CipherSuite() SignatureProtocol {
	return &cipherSuite{
		curve: p.curve,
		hash:  p.hash,
	}
}

func (*protocol) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}
