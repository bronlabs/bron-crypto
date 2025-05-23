package trsa

import (
	"crypto/rsa"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
)

type PublicShard struct {
	N1 *saferith.Modulus
	N2 *saferith.Modulus
	E  uint64
}

type Shard struct {
	PublicShard
	D1Share *rep23.IntShare
	D2Share *rep23.IntShare
}

func (s *PublicShard) PublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: new(big.Int).Mul(s.N1.Big(), s.N2.Big()),
		E: int(s.E),
	}
}
