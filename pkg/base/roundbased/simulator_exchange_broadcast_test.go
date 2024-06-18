package roundbased

import (
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"testing"
	"time"
)

func Test_BroadcastExchange(t *testing.T) {
	participants, err := testutils.MakeDeterministicTestIdentities(4)
	require.NoError(t, err)
	router := NewSimulatorBroadcastExchanger[string](hashset.NewHashableHashSet(participants...))

	worker := func(me types.IdentityKey) error {
		sent := fmt.Sprintf("[%s -> everybody]", me.String())
		router.Send(me, sent)
		received := router.Receive(me)
		for iter := received.Iterator(); iter.HasNext(); {
			e := iter.Next()
			from := e.Key
			payload := e.Value
			fmt.Printf("%s received %s from %s\n", me.String(), payload, from.String())
		}
		return nil
	}

	errChan := make(chan error)
	go func() {
		var group errgroup.Group
		for _, i := range participants {
			group.Go(func() error {
				return worker(i)
			})
		}
		errChan <- group.Wait()
	}()

	select {
	case err = <-errChan:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		require.Fail(t, "no response")
	}
}
