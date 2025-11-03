package rfc9380

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380/expanders"
)

type MessageExpander interface {
	ExpandMessage(dst, msg []byte, outLen uint) []byte
}

func NewXMDMessageExpander[H hash.Hash](hashFunc func() H) MessageExpander {
	return &expanders.Xmd{HashFunc: func() hash.Hash { return hashFunc() }}
}

func NewXOFMessageExpander(shakeHash hash.XOF, k uint) MessageExpander {
	return &expanders.Xof{
		XofHash: shakeHash,
		K:       k,
	}
}
