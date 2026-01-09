package rfc9380

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380/expanders"
)

// MessageExpander expands messages per RFC 9380 hash-to-curve.
type MessageExpander interface {
	// ExpandMessage expands msg to outLen using dst.
	ExpandMessage(dst, msg []byte, outLen uint) []byte
}

// NewXMDMessageExpander returns an XMD expander for the given hash.
func NewXMDMessageExpander[H hash.Hash](hashFunc func() H) MessageExpander {
	return &expanders.Xmd{HashFunc: func() hash.Hash { return hashFunc() }}
}

// NewXOFMessageExpander returns an XOF expander for the given XOF hash and security parameter k.
func NewXOFMessageExpander(shakeHash hash.XOF, k uint) MessageExpander {
	return &expanders.Xof{
		XofHash: shakeHash,
		K:       k,
	}
}
