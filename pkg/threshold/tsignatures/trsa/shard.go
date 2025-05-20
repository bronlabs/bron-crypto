package trsa

import (
	"crypto/rsa"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
)

type Shard struct {
	D1Share *rep23.IntShare
	D2Share *rep23.IntShare

	N1         *saferith.Modulus
	N2         *saferith.Modulus
	E          uint64
	PaddingKey [32]byte
}

func (s *Shard) PublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: new(big.Int).Mul(s.N1.Big(), s.N2.Big()),
		E: int(s.E),
	}
}
