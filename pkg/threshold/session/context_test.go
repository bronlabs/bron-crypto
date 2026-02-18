package session_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/threshold/session"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

func Test_ContextSampleZeroShare(t *testing.T) {
	t.Parallel()
	prng := pcg.New(505, 606)
	curve := k256.NewCurve()

	ctxs := sampleContexts(t, 4, prng)
	sum := curve.OpIdentity()
	for id := range ctxs {
		share, err := session.SampleZeroShare(ctxs[id], curve)
		require.NoError(t, err)
		sum = sum.Op(share.Value())
	}
	require.True(t, sum.IsOpIdentity())
}

func Test_SubContextTranscriptAndZeroShare(t *testing.T) {
	t.Parallel()
	prng := pcg.New(303, 404)
	curve := k256.NewCurve()

	ctxs := sampleContexts(t, 4, prng)
	subQuorum := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()

	subCtxs := make(map[sharing.ID]*session.Context)
	for id := range subQuorum.Iter() {
		subCtx, err := ctxs[id].SubContext(subQuorum)
		require.NoError(t, err)
		subCtxs[id] = subCtx
	}

	sum := curve.OpIdentity()
	for id := range subQuorum.Iter() {
		share, err := session.SampleZeroShare(subCtxs[id], curve)
		require.NoError(t, err)
		sum = sum.Op(share.Value())
	}
	require.True(t, sum.IsOpIdentity())

	baseChallenge, err := ctxs[sharing.ID(1)].Transcript().ExtractBytes("challenge", 32)
	require.NoError(t, err)
	subChallenge, err := subCtxs[sharing.ID(1)].Transcript().ExtractBytes("challenge", 32)
	require.NoError(t, err)
	require.NotEqual(t, baseChallenge, subChallenge)
}

func sampleContexts(tb testing.TB, n int, prng io.Reader) map[sharing.ID]*session.Context {
	tb.Helper()
	parties := sharing.NewOrdinalShareholderSet(uint(n))

	commonSeed := make([]byte, 64)
	_, err := io.ReadFull(prng, commonSeed)
	require.NoError(tb, err)

	pairwiseSeeds := make(map[sharing.ID]map[sharing.ID][]byte)
	for i := 1; i <= n; i++ {
		pairwiseSeeds[sharing.ID(i)] = make(map[sharing.ID][]byte)
	}
	for i := 1; i <= n; i++ {
		for j := i + 1; j <= n; j++ {
			seed := make([]byte, 64)
			_, err := io.ReadFull(prng, seed)
			require.NoError(tb, err)

			pairwiseSeeds[sharing.ID(i)][sharing.ID(j)] = seed
			pairwiseSeeds[sharing.ID(j)][sharing.ID(i)] = seed
		}
	}

	ctxs := make(map[sharing.ID]*session.Context)
	for i := 1; i <= n; i++ {
		ctxs[sharing.ID(i)], err = session.NewContext(sharing.ID(i), parties, commonSeed, pairwiseSeeds[sharing.ID(i)])
		require.NoError(tb, err)
	}

	return ctxs
}
