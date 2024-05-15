package fuzzutils

import (
	"testing"

	"github.com/stretchr/testify/require"
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
