package rapidext

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"pgregory.net/rapid"
)

func UniformDomainElement[V any](domain algebra.FiniteStructure[V]) *rapid.Generator[V] {
	genFunc := func(t *rapid.T) V {
		entropyLen := domain.ElementSize()
		entropyData := rapid.SliceOfN(rapid.Byte(), 0, entropyLen).Draw(t, "preimage")
		return errs2.Must1(domain.Hash(entropyData))
	}
	return rapid.Custom(genFunc)
}
