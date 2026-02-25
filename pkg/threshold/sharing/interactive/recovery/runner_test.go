package recovery_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/interactive/recovery"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/interactive/recovery/testutils"
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

	ac, err := accessstructures.NewThresholdAccessStructure(2, hashset.NewComparable[sharing.ID](1, 2, 3, 4).Freeze())
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
