package redistribute_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
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

func TestRunner_HappyPathRecover(t *testing.T) {
	t.Parallel()

	testRunnerHappyRecover(t, k256.NewCurve())
}

func testRunnerHappyRecover[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S]) {
	tb.Helper()

	prng := pcg.NewRandomised()
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	secretValue, err := field.Random(prng)
	require.NoError(tb, err)

	shareholders := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
	as, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(tb, err)
	shards := testutils.Deal(tb, as, group, secretValue)

	recoverers := hashset.NewComparable[sharing.ID](2, 3).Freeze()
	ctxs := session_testutils.MakeRandomContexts(tb, shareholders, prng)

	runners := make(map[sharing.ID]network.Runner[*redistribute.BaseShard[G, S]], len(ctxs))
	for id, ctx := range ctxs {
		var shard *redistribute.BaseShard[G, S]
		if recoverers.Contains(id) {
			shard = shards[id]
		}

		runner, err := redistribute.NewRunner(ctx, recoverers, shard, as, pcg.NewRandomised())
		require.NoError(tb, err)
		runners[id] = runner
	}

	newShards := ntu.TestExecuteRunners(tb, runners)

	scheme, err := feldman.NewScheme(group, as)
	require.NoError(tb, err)
	for id := range as.Shareholders().Iter() {
		shard, ok := newShards[id]
		require.True(tb, ok)
		require.NotNil(tb, shard)

		err = scheme.Verify(shard.Share, shard.VerificationVector)
		require.NoError(tb, err)
	}

	for ids := range sliceutils.KCoveringCombinations(as.Shareholders().List(), 2) {
		shares := sliceutils.Map(ids, func(id sharing.ID) *kw.Share[S] { return newShards[id].Share })
		newSecret, err := scheme.Reconstruct(shares...)
		require.NoError(tb, err)
		require.True(tb, newSecret.Value().Equal(secretValue))
	}
}
