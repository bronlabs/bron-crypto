package properties

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"pgregory.net/rapid"
)

func UniformDomainGenerator[E algebra.Element[E]](domain algebra.FiniteStructure[E]) *rapid.Generator[E] {
	genFunc := func(t *rapid.T) E {
		entropyLen := domain.ElementSize()
		entropyData := rapid.SliceOfN(rapid.Byte(), 0, entropyLen).Draw(t, "preimage")
		return errs2.Must1(domain.Hash(entropyData))
	}
	return rapid.Custom(genFunc)
}
