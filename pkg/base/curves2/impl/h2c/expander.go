package h2c

import (
	"hash"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves2/impl/h2c/expanders"
)

type MessageExpander interface {
	ExpandMessage(dst, msg []byte, outLen uint) []byte
}

func NewXMDMessageExpander(hashFunc func() hash.Hash) MessageExpander {
	return &expanders.Xmd{HashFunc: hashFunc}
}

func NewXOFMessageExpander(shakeHash sha3.ShakeHash, k uint) MessageExpander {
	return &expanders.Xof{
		XofHash: shakeHash.Clone(),
		K:       k,
	}
}
