package testutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"hash"
)

var (
	_ fuzzutils.ObjectAdapter[types.SigningSuite] = (*SigningSuiteAdapter)(nil)
)

type SigningSuiteAdapter struct {
	curveAdapter fuzzutils.ObjectAdapter[curves.Curve]
	hashAdapter  fuzzutils.ObjectAdapter[func() hash.Hash]
}

func NewSigningSuiteAdapter(curveAdapter fuzzutils.ObjectAdapter[curves.Curve], hashAdapter fuzzutils.ObjectAdapter[func() hash.Hash]) *SigningSuiteAdapter {
	return &SigningSuiteAdapter{
		curveAdapter: curveAdapter,
		hashAdapter:  hashAdapter,
	}
}

func (s *SigningSuiteAdapter) Wrap(pt fuzzutils.ObjectUnderlyer) types.SigningSuite {
	curveUnderlayer := pt
	hashUnderlayer := pt ^ 0xd5262db6808ca67c

	return &CipherSuite{
		curve: s.curveAdapter.Wrap(curveUnderlayer),
		hash:  s.hashAdapter.Wrap(hashUnderlayer),
	}
}

func (s *SigningSuiteAdapter) Unwrap(t types.SigningSuite) fuzzutils.ObjectUnderlyer {
	panic("not supported")
}

func (s *SigningSuiteAdapter) ZeroValue() types.SigningSuite {
	return &CipherSuite{
		curve: s.curveAdapter.ZeroValue(),
		hash:  s.hashAdapter.ZeroValue(),
	}
}
