package canetti_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/canetti"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/stretchr/testify/require"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()
	group := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(4)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	shards := testHappyPath(t, group, accessStructure)

	t.Run("shares are valid", func(t *testing.T) {
		t.Parallel()

		scheme, err := feldman.NewScheme(group, accessStructure)
		require.NoError(t, err)
		for _, shard := range shards {
			err := scheme.Verify(shard.Share(), shard.VerificationVector())
			require.NoError(t, err)
		}
	})

	t.Run("verification vector matches", func(t *testing.T) {
		t.Parallel()

		ref := shards[shareholders.List()[0]].VerificationVector()
		for _, shard := range shards {
			require.True(t, ref.Equal(shard.VerificationVector()))
		}
	})

	t.Run("shares can reconstruct to the same value", func(t *testing.T) {
		t.Parallel()

		allShares := iterutils.Map(maps.Values(shards), func(s *mpc.BaseShard[*k256.Point, *k256.Scalar]) *feldman.Share[*k256.Scalar] { return s.Share() })
		scheme, err := feldman.NewScheme(group, accessStructure)
		require.NoError(t, err)
		secret, err := scheme.Reconstruct(slices.Collect(allShares)...)
		require.NoError(t, err)
		ref := secret.Value()

		for subIds := range sliceutils.KCoveringCombinations(shareholders.List(), 2) {
			shares := sliceutils.Map(subIds, func(id sharing.ID) *feldman.Share[*k256.Scalar] { return shards[id].Share() })
			reconstructed, err := scheme.Reconstruct(shares...)
			require.NoError(t, err)
			require.True(t, ref.Equal(reconstructed.Value()))
		}
	})
}

func testHappyPath[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S], accessStructure accessstructures.Monotone) map[sharing.ID]*mpc.BaseShard[G, S] {
	tb.Helper()

	var err error
	prng := pcg.NewRandomised()
	ctxs := session_testutils.MakeRandomContexts(tb, accessStructure.Shareholders(), prng)
	participants := make(map[sharing.ID]*canetti.Participant[G, S])
	for id, ctx := range ctxs {
		p, err := canetti.NewParticipant(ctx, accessStructure, group, pcg.NewRandomised())
		require.NoError(tb, err)
		participants[id] = p
	}

	r1bOut := make(map[sharing.ID]*canetti.Round1Broadcast[G, S])
	for id, p := range participants {
		r1bOut[id], err = p.Round1()
		require.NoError(tb, err)
	}

	r2bIn := ntu.MapBroadcastO2I(tb, slices.Collect(maps.Values(participants)), r1bOut)
	r2bOut := make(map[sharing.ID]*canetti.Round2Broadcast[G, S])
	r2uOut := make(map[sharing.ID]network.OutgoingUnicasts[*canetti.Round2P2P[G, S], *canetti.Participant[G, S]])
	for id, p := range participants {
		r2bOut[id], r2uOut[id], err = p.Round2(r2bIn[id])
		require.NoError(tb, err)
	}

	r3bIn, r3uIn := ntu.MapO2I(tb, slices.Collect(maps.Values(participants)), r2bOut, r2uOut)
	r3bOut := make(map[sharing.ID]*canetti.Round3Broadcast[G, S])
	for id, p := range participants {
		r3bOut[id], err = p.Round3(r3bIn[id], r3uIn[id])
		require.NoError(tb, err)

	}

	r4bIn := ntu.MapBroadcastO2I(tb, slices.Collect(maps.Values(participants)), r3bOut)
	baseShards := make(map[sharing.ID]*mpc.BaseShard[G, S])
	for id, p := range participants {
		baseShards[id], err = p.Round4(r4bIn[id])
		require.NoError(tb, err)
	}

	return baseShards
}
