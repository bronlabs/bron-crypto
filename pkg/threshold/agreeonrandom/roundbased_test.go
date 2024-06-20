package agreeonrandom_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased/simulator"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
)

func Test_HappyPathRandomRoundBasedRunner(t *testing.T) {
	t.Parallel()

	participants, err := testutils.MakeParticipants(3)
	require.NoError(t, err)
	identities := participants[0].Protocol.Participants()

	results := make([][]byte, len(participants))
	errChan := make(chan error)
	go func() {
		router := simulator.NewEchoBroadcastMessageRouter(identities)
		var errGrp errgroup.Group
		for i, participant := range participants {
			errGrp.Go(func() error {
				var err error
				results[i], err = agreeonrandom.RoundBasedRunner(router, participant)
				return err
			})
		}
		errChan <- errGrp.Wait()
	}()

	select {
	case err = <-errChan:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		require.Fail(t, "timeout")
	}

	t.Run("all randoms equal", func(t *testing.T) {
		t.Parallel()

		for i := 0; i < len(results)-1; i++ {
			require.Equal(t, results[i], results[i+1])
		}
	})
}
