package redistribute_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/redistribute"
	"github.com/bronlabs/bron-crypto/pkg/mpc/redistribute/testutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func Test_HappyPathRefresh(t *testing.T) {
	t.Parallel()

	testHappyPathRefresh(t, k256.NewCurve())
}

func testHappyPathRefresh[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S]) {
	tb.Helper()

	const th = 2
	const n = 3
	prng := pcg.NewRandomised()
	shareholders := sharing.NewOrdinalShareholderSet(n)
	as, err := threshold.NewThresholdAccessStructure(th, shareholders)
	require.NoError(tb, err)
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	secretValue, err := field.Random(prng)
	require.NoError(tb, err)

	oldShards := testutils.Deal(tb, as, group, secretValue)
	ctxs := session_testutils.MakeRandomContexts(tb, shareholders, prng)
	participants := maputils.MapValues(oldShards, func(id sharing.ID, shard *mpc.BaseShard[G, S]) *redistribute.Participant[G, S] {
		p, err := redistribute.NewParticipant(ctxs[id], as.Shareholders(), oldShards[id], as, pcg.NewRandomised())
		require.NoError(tb, err)
		return p
	})

	r1bo := make(map[sharing.ID]*redistribute.Round1Broadcast[G, S])
	r1uo := make(map[sharing.ID]network.RoundMessages[*redistribute.Round1P2P[G, S], *redistribute.Participant[G, S]])
	for id, p := range participants {
		r1bo[id], r1uo[id], err = p.Round1()
		require.NoError(tb, err)
	}

	r2bi, r2ui := ntu.MapO2I(tb, slices.Collect(maps.Values(participants)), r1bo, r1uo)
	newShards := make(map[sharing.ID]*mpc.BaseShard[G, S])
	for id, p := range participants {
		newShards[id], err = p.Round2(r2bi[id], r2ui[id])
		require.NoError(tb, err)
	}

	// new shares are valid
	scheme, err := feldman.NewScheme(group, as)
	require.NoError(tb, err)
	for _, shard := range newShards {
		err := scheme.Verify(shard.Share(), shard.VerificationVector())
		require.NoError(tb, err)
	}

	// new shares are refreshed but keep the same public key
	for id := range as.Shareholders().Iter() {
		require.False(tb, oldShards[id].Share().Equal(newShards[id].Share()))
		require.False(tb, oldShards[id].VerificationVector().Equal(newShards[id].VerificationVector()))

		oldPk, _ := oldShards[id].VerificationVector().Value().Get(0, 0)
		newPk, _ := newShards[id].VerificationVector().Value().Get(0, 0)
		require.True(tb, oldPk.Equal(newPk))
	}

	// new shares reconstruct to the same value
	for ids := range sliceutils.KCoveringCombinations(shareholders.List(), th) {
		shares := sliceutils.Map(ids, func(id sharing.ID) *kw.Share[S] { return newShards[id].Share() })
		newSecret, err := scheme.Reconstruct(shares...)
		require.NoError(tb, err)
		require.True(tb, newSecret.Value().Equal(secretValue))
	}
}
