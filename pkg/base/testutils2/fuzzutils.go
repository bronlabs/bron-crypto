package testutils2

import (
	"math/rand/v2"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/fkechacha20"
	"github.com/stretchr/testify/require"
)

const prngSalt = "KRYPTON_FUZZUTIL_PRNG_SALT-"

type fuzzerPrng = fkechacha20.Prng

var defaultSeed = make([]byte, fkechacha20.ChachaPRNGSecurityStrength)

func NewPrng(seed []byte) (csprng.Seedable, error) {
	r := rand.NewPCG(42, 1024)
	if len(seed) == 0 {
		seed = defaultSeed
	}
	return fkechacha20.NewPrng(seed, []byte(prngSalt))
}

type CollectionPropertyTester[C Collection[O], O Object] struct {
	g CollectionGenerator[C, O]
}

func (pt *CollectionPropertyTester[C, O]) Run(f *testing.F, invariantChecker func(t *testing.T, g CollectionGenerator[C, O])) {
	f.Fuzz(func(t *testing.T, seed []byte) {
		pt.g.Reseed(seed)
		invariantChecker(t, pt.g)
	})
}

func NewCollectionPropertyTester[C Collection[O], O Object](f *testing.F, seeds [][]byte, generator func(prng csprng.Seedable) (CollectionGenerator[C, O], error)) *CollectionPropertyTester[C, O] {
	f.Helper()
	prng, err := NewPrng(nil)
	require.NoError(f, err)
	g, err := generator(prng)
	require.NoError(f, err)

	for _, seed := range seeds {
		f.Add(seed)
	}
	return &CollectionPropertyTester[C, O]{g}
}
