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

type BaseProtocol struct {
	curve        curves.Curve
	hash         func() hash.Hash
	participants ds.Set[IdentityKey]
	threshold    uint
}

func NewBaseProtocol(curve curves.Curve, hashFunc func() hash.Hash, participants ds.Set[IdentityKey], threshold uint) *BaseProtocol {
	return &BaseProtocol{
		curve:        curve,
		hash:         hashFunc,
		participants: participants,
		threshold:    threshold,
	}
}

func (p *BaseProtocol) Curve() curves.Curve {
	return p.curve
}

func (p *BaseProtocol) Hash() func() hash.Hash {
	return p.hash
}

func (p *BaseProtocol) Participants() ds.Set[IdentityKey] {
	return p.participants
}

func (p *BaseProtocol) Threshold() uint {
	return p.threshold
}

func (p *BaseProtocol) TotalParties() uint {
	return uint(p.participants.Size())
}

func (p *BaseProtocol) CipherSuite() SignatureProtocol {
	return &cipherSuite{
		curve: p.curve,
		hash:  p.hash,
	}
}

func (*BaseProtocol) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}
