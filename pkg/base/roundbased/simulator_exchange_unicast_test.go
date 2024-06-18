package roundbased

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
)

func Test_UnicastExchange(t *testing.T) {
	participants, err := testutils.MakeDeterministicTestIdentities(4)
	require.NoError(t, err)
	router := NewSimulatorUnicastExchanger[int](hashset.NewHashableHashSet(participants...))

	worker := func(me types.IdentityKey) {
		sent := hashmap.NewHashableHashMap[types.IdentityKey, int]()
		for i, p := range participants {
			if p.Equal(me) {
				continue
			}
			sent.Put(p, i*100)
		}

		router.Send(me, sent)
		received := router.Receive(me)
		for iter := received.Iterator(); iter.HasNext(); {
			e := iter.Next()
			fmt.Printf("%s: received %d from %s\n", me.String(), e.Value, e.Key.String())
		}
	}

	errChan := make(chan error)
	go func() {
		var group errgroup.Group
		for _, i := range participants {
			group.Go(func() error {
				worker(i)
				return nil
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
