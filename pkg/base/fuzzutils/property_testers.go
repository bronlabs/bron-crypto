package fuzzutils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

func RunCollectionPropertyTest[C Collection[O], O Object](f *testing.F, seedCorpus [][2]uint64, checkInvariants func(*testing.T, CollectionGenerator[C, O]), generator CollectionGenerator[C, O]) {
	f.Helper()
	require.NotNil(f, generator)
	f.Add(uint64(0), uint64(0)) // this is to shut off the warning
	for _, seedPair := range seedCorpus {
		f.Add(seedPair[0], seedPair[1])
	}
	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		g := generator.Clone()
		g.Reseed(seed1, seed2)
		checkInvariants(t, g)
	})
}

func RunAlgebraPropertyTest[S algebra.Structure, E algebra.Element](f *testing.F, checkInvariants func(*testing.T, S, ObjectGenerator[E]), structure S, generators ...ObjectGenerator[E]) {
	f.Helper()
	require.GreaterOrEqual(f, len(generators), 1)
	for _, g := range generators {
		require.NotNil(f, g)
	}
	f.Add(uint64(0), uint64(0)) // this is to shut off the warning

	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		for i, generator := range generators {
			t.Run(fmt.Sprintf("generator=%d", i), func(t *testing.T) {
				t.Helper()
				g := generator.Clone()
				g.Reseed(seed1, seed2)
				checkInvariants(t, structure, g)
			})
		}
	})
}
