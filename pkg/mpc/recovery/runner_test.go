package recovery_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/recovery"
	"github.com/bronlabs/bron-crypto/pkg/mpc/recovery/testutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

type outputlessRunnerAdapter struct {
	runner network.Runner[any]
}

func (a outputlessRunnerAdapter) Run(rt *network.Router) (*recovery.Output[*k256.Point, *k256.Scalar], error) {
	_, err := a.runner.Run(rt)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func TestRunnerHappyPath(t *testing.T) {
	t.Parallel()

	ac, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable[sharing.ID](1, 2, 3, 4).Freeze())
	require.NoError(t, err)
	mislayerId := sharing.ID(3)
	shard, mislayers, recoverers := testutils.MakeRunners(t, ac, mislayerId)

	runners := make(map[sharing.ID]network.Runner[*recovery.Output[*k256.Point, *k256.Scalar]], len(mislayers)+len(recoverers))
	for id, recoverer := range recoverers {
		runners[id] = outputlessRunnerAdapter{runner: recoverer}
	}
	for id, mislayer := range mislayers {
		runners[id] = mislayer
	}

	outputs := ntu.TestExecuteRunnersWithQuorum(t, ac.Shareholders(), runners)
	recoveredOutput, ok := outputs[mislayerId]
	require.True(t, ok)
	require.NotNil(t, recoveredOutput)

	require.True(t, shard.Share().Equal(recoveredOutput.Share()))
}

func TestRunnerHappyPath_WithQualifiedSubQuorum(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	group := k256.NewCurve()
	ac, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable[sharing.ID](1, 2, 3, 4).Freeze())
	require.NoError(t, err)

	recoveryQuorum := hashset.NewComparable[sharing.ID](2, 3, 4).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, recoveryQuorum, prng)

	scheme, err := feldman.NewScheme(group.Generator(), ac)
	require.NoError(t, err)
	dealerOutput, _, err := scheme.DealRandom(prng)
	require.NoError(t, err)
	verificationVector := dealerOutput.VerificationMaterial()

	mislayerID := sharing.ID(3)
	mislayerRunner, err := recovery.NewMislayerRunner(ctxs[mislayerID], ac, group)
	require.NoError(t, err)

	runners := map[sharing.ID]network.Runner[*recovery.Output[*k256.Point, *k256.Scalar]]{
		mislayerID: mislayerRunner,
	}
	for _, id := range []sharing.ID{2, 4} {
		share, ok := dealerOutput.Shares().Get(id)
		require.True(t, ok)
		shard, err := tsig.NewBaseShard(share, verificationVector, ac)
		require.NoError(t, err)
		recovererRunner, err := recovery.NewRecovererRunner(ctxs[id], mislayerID, shard, prng)
		require.NoError(t, err)
		runners[id] = outputlessRunnerAdapter{runner: recovererRunner}
	}

	outputs := ntu.TestExecuteRunnersWithQuorum(t, recoveryQuorum, runners)
	recoveredOutput, ok := outputs[mislayerID]
	require.True(t, ok)
	require.NotNil(t, recoveredOutput)

	lostShare, ok := dealerOutput.Shares().Get(mislayerID)
	require.True(t, ok)
	require.True(t, lostShare.Equal(recoveredOutput.Share()))
}
