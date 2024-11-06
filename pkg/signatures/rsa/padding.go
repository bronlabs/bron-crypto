package rsa

import (
	"hash"
	"math/big"
)

type Padding interface {
	HashAndPad(bitLen int, hashFunc func() hash.Hash, message []byte) (*big.Int, error)
}
