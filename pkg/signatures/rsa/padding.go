package rsa

import (
	"hash"

	"github.com/cronokirby/saferith"
)

type Padding interface {
	HashAndPad(bitLen int, hashFunc func() hash.Hash, message []byte) (*saferith.Nat, error)
}
