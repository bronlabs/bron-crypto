package redistribute_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/redistribute"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func Test_HappyPathRecover(t *testing.T) {
	t.Parallel()

	testHappyRecover(t, k256.NewCurve())
}

func testHappyRecover[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S]) {
	tb.Helper()

	prng := pcg.NewRandomised()

	shareholders := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
	as, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(tb, err)
	shards, secret := dealShards(tb, as, group)

	recoverers := hashset.NewComparable[sharing.ID](2, 3).Freeze()
	ctxs := session_testutils.MakeRandomContexts(tb, shareholders, prng)
	participants := make(map[sharing.ID]*redistribute.Participant[G, S])
	for id := range shareholders.Iter() {
		var shard *mpc.BaseShard[G, S]
		if recoverers.Contains(id) {
			shard = shards[id]
		}
		p, err := redistribute.NewParticipant(ctxs[id], recoverers, shard, as, pcg.NewRandomised(), redistribute.WithTrustedAnchorID(2))
		require.NoError(tb, err)
		participants[id] = p
	}

	r1bo := make(map[sharing.ID]*redistribute.Round1Broadcast[G, S])
	r1uo := make(map[sharing.ID]network.RoundMessages[*redistribute.Round1P2P[G, S], *redistribute.Participant[G, S]])
	for id, p := range participants {
		r1bo[id], r1uo[id], err = p.Round1()
		require.NoError(tb, err)
	}

	r2bi, r2ui := ntu.MapO2I(tb, slices.Collect(maps.Values(participants)), r1bo, r1uo)
	r2bo := make(map[sharing.ID]*redistribute.Round2Broadcast[G, S])
	r2uo := make(map[sharing.ID]network.RoundMessages[*redistribute.Round2P2P[G, S], *redistribute.Participant[G, S]])
	for id, p := range participants {
		r2bo[id], r2uo[id], err = p.Round2(r2bi[id], r2ui[id])
		require.NoError(tb, err)
	}

	r3bi, r3ui := ntu.MapO2I(tb, slices.Collect(maps.Values(participants)), r2bo, r2uo)
	newShards := make(map[sharing.ID]*mpc.BaseShard[G, S])
	for id, p := range participants {
		newShards[id], err = p.Round3(r3bi[id], r3ui[id])
		require.NoError(tb, err)
	}

	// new shares are valid
	scheme, err := feldman.NewScheme(group, as)
	require.NoError(tb, err)
	for id := range as.Shareholders().Iter() {
		shard, ok := newShards[id]
		require.True(tb, ok)
		err := scheme.Verify(shard.Share(), shard.VerificationVector())
		require.NoError(tb, err)
	}

	// new shares reconstruct to the same value
	for ids := range sliceutils.KCoveringCombinations(as.Shareholders().List(), 2) {
		shares := sliceutils.Map(ids, func(id sharing.ID) *kw.Share[S] { return newShards[id].Share() })
		newSecret, err := scheme.Reconstruct(shares...)
		require.NoError(tb, err)
		require.True(tb, newSecret.Value().Equal(secret.Value()))
	}
}
