package testutils

import (
	"crypto/sha256"
	"crypto/sha512"
	"github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"golang.org/x/crypto/sha3"
	"hash"
)

var (
	_ fuzzutils.ObjectAdapter[func() hash.Hash] = (*Hash256Adapter)(nil)
	_ fuzzutils.ObjectAdapter[func() hash.Hash] = (*Hash512Adapter)(nil)
)

type Hash256Adapter struct{}

type Hash512Adapter struct{}

func NewHash256Adapter() *Hash256Adapter {
	return &Hash256Adapter{}
}

func (h *Hash256Adapter) Wrap(underlyer fuzzutils.ObjectUnderlyer) func() hash.Hash {
	idx := int(underlyer) % len(hash256funcs)
	return hash256funcs[idx]
}

func (h *Hash256Adapter) Unwrap(_ func() hash.Hash) fuzzutils.ObjectUnderlyer {
	panic("not supported")
}

func (h *Hash256Adapter) ZeroValue() func() hash.Hash {
	return nil
}

func NewHash512Adapter() *Hash512Adapter {
	return &Hash512Adapter{}
}

func (h *Hash512Adapter) Wrap(underlyer fuzzutils.ObjectUnderlyer) func() hash.Hash {
	idx := int(underlyer) % len(hash512funcs)
	return hash512funcs[idx]
}

func (h *Hash512Adapter) Unwrap(_ func() hash.Hash) fuzzutils.ObjectUnderlyer {
	panic("not supported")
}

func (h *Hash512Adapter) ZeroValue() func() hash.Hash {
	return nil
}

var hash256funcs = []func() hash.Hash{
	sha256.New,
	sha3.New256,
}

var hash512funcs = []func() hash.Hash{
	sha512.New,
	sha3.New512,
}
