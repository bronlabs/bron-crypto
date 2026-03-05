package session_testutils

import (
	"io"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/stretchr/testify/require"
)

func MakeRandomContexts(tb testing.TB, quorum network.Quorum, prng io.Reader) map[sharing.ID]*session.Context {
	tb.Helper()

	commonSeed := make([]byte, 64)
	_, err := io.ReadFull(prng, commonSeed)
	require.NoError(tb, err)

	sortedIds := quorum.List()
	slices.Sort(sortedIds)
	pairwiseSeeds := make(map[sharing.ID]map[sharing.ID][]byte)
	for _, id := range sortedIds {
		pairwiseSeeds[id] = make(map[sharing.ID][]byte)
	}

	for i := range sortedIds {
		for j := range sortedIds {
			seed := make([]byte, 64)
			_, err := io.ReadFull(prng, seed)
			require.NoError(tb, err)

			pairwiseSeeds[sortedIds[i]][sortedIds[j]] = seed
			pairwiseSeeds[sortedIds[j]][sortedIds[i]] = seed
		}
	}

	ctxs := make(map[sharing.ID]*session.Context)
	for _, id := range sortedIds {
		ctxs[id], err = session.NewContext(id, quorum, commonSeed, pairwiseSeeds[id])
		require.NoError(tb, err)
	}

	return ctxs
}
