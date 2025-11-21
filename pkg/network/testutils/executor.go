package ntu

import (
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestExecuteRunners[O any](tb testing.TB, runners map[sharing.ID]network.Runner[O]) map[sharing.ID]O {
	tb.Helper()

	results := make(map[sharing.ID]O)
	var resultsMutex sync.Mutex
	testCoordinator := NewMockCoordinator(slices.Collect(maps.Keys(runners))...)

	var errGroup errgroup.Group
	for id, runner := range runners {
		errGroup.Go(func() error {
			rt := network.NewRouter(testCoordinator.DeliveryFor(id))
			result, err := runner.Run(rt)
			if err != nil {
				return err
			}

			resultsMutex.Lock()
			defer resultsMutex.Unlock()
			results[id] = result
			return nil
		})
	}

	err := errGroup.Wait()
	require.NoError(tb, err)
	return results
}
