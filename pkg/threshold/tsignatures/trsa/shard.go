package trsa

import (
	"crypto/rsa"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
)

var (
	_ datastructures.Equatable[*PublicShard] = (*PublicShard)(nil)
	_ datastructures.Equatable[*Shard]       = (*Shard)(nil)
)

type PublicShard struct {
	N1 *saferith.Modulus
	N2 *saferith.Modulus
	E  uint64
}

func (s *PublicShard) Equal(rhs *PublicShard) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}

	if _, eq, _ := s.N1.Cmp(rhs.N1); eq == 0 {
		return false
	}
	if _, eq, _ := s.N2.Cmp(rhs.N2); eq == 0 {
		return false
	}
	if s.E != rhs.E {
		return false
	}

	return true
}

func (s *PublicShard) PublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: new(big.Int).Mul(s.N1.Big(), s.N2.Big()),
		E: int(s.E),
	}
}

type Shard struct {
	PublicShard
	D1Share *rep23.IntShare
	D2Share *rep23.IntShare
}

func (s *Shard) Equal(rhs *Shard) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}

	if !s.PublicShard.Equal(&rhs.PublicShard) {
		return false
	}
	if !s.D1Share.Equal(rhs.D1Share) {
		return false
	}
	if !s.D2Share.Equal(rhs.D2Share) {
		return false
	}

	return true
}
