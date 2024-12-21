package riss_test

import (
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_RhoMapping(t *testing.T) {
	t.Parallel()

	for _, ac := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", ac.th, ac.n), func(t *testing.T) {
			t.Parallel()

			unqualifiedSets, err := riss.BuildSortedMaxUnqualifiedSets(ac.th, ac.n)
			require.NoError(t, err)

			rhoMap, err := riss.BuildRhoMapping(unqualifiedSets, ac.n)
			require.NoError(t, err)
			require.Len(t, rhoMap, len(unqualifiedSets))
			for _, v := range rhoMap {
				require.Len(t, v, len(unqualifiedSets))
			}
		})
	}
}

func Test_ChiMapping(t *testing.T) {
	t.Parallel()

	for _, ac := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", ac.th, ac.n), func(t *testing.T) {
			t.Parallel()

			chiMap := riss.BuildChiMapping(ac.th, ac.n)
			require.Len(t, chiMap, int(ac.n))
		})
	}
}
