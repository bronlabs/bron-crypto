package properties

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"pgregory.net/rapid"
)

func FiniteStructureElement[V any](structure algebra.FiniteStructure[V]) *rapid.Generator[V] {
	genFunc := func(t *rapid.T) V {
		entropyLen := structure.ElementSize()
		entropyData := rapid.SliceOfN(rapid.Byte(), 0, entropyLen).Draw(t, "preimage")
		return errs2.Must1(structure.Hash(entropyData))
	}
	return rapid.Custom(genFunc)
}
