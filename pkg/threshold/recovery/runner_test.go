package recovery_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/recovery"
	"github.com/bronlabs/bron-crypto/pkg/threshold/recovery/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

func TestRunnerHappyPath(t *testing.T) {
	t.Parallel()

	ac, err := sharing.NewThresholdAccessStructure(2, hashset.NewComparable[sharing.ID](1, 2, 3, 4).Freeze())
	require.NoError(t, err)
	mislayerId := sharing.ID(3)
	shard, mislayers, recoverers := testutils.MakeRunners(t, ac, mislayerId)
	var recoveredOutput *recovery.Output[*k256.Point, *k256.Scalar]

	// this one has to be run manually due to a non-symmetrical communication scheme
	coordinator := ntu.NewMockCoordinator(ac.Shareholders().List()...)
	var errGroup errgroup.Group
	for id, recoverer := range recoverers {
		delivery := coordinator.DeliveryFor(id)
		router := network.NewRouter(delivery)
		errGroup.Go(func() error {
			_, err = recoverer.Run(router)
			return err
		})
	}
	for id, mislayer := range mislayers {
		delivery := coordinator.DeliveryFor(id)
		router := network.NewRouter(delivery)
		errGroup.Go(func() error {
			recoveredOutput, err = mislayer.Run(router)
			return err
		})
	}
	err = errGroup.Wait()
	require.NoError(t, err)

	require.True(t, shard.Share().Equal(recoveredOutput.Share()))
}
