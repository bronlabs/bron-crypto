package roundbased_test

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"math/rand/v2"
	"testing"
)

type exampleRound1BroadcastMessage struct {
	val int
}

func exampleBroadcastProtocol(router roundbased.MessageRouter, party types.IdentityKey, participants datastructures.Set[types.IdentityKey]) int {
	round1 := roundbased.NewSimulatorRound[*exampleRound1BroadcastMessage, any, any, any](router, 1, party)
	round2 := roundbased.NewSimulatorRound[any, *exampleRound1BroadcastMessage, any, any](router, 2, party)

	localValue := rand.N[int](1000)
	err := round1.SendBroadcast(&exampleRound1BroadcastMessage{localValue})
	if err != nil {
		panic(err)
	}

	r2Input, err := round2.ReceiveBroadcast()
	if err != nil {
		panic(err)
	}

	for iter := participants.Iterator(); iter.HasNext(); {
		id := iter.Next()
		if id.Equal(party) {
			continue
		}

		remoteValue, ok := r2Input.Get(id)
		if !ok {
			panic("no message from party " + id.String())
		}

		localValue = localValue + remoteValue.val
	}

	return localValue
}

func Test_Broadcast(t *testing.T) {
	const n = 5

	ids, err := testutils.MakeDeterministicTestIdentities(n)
	require.NoError(t, err)
	participants := hashset.NewHashableHashSet(ids...)

	router := roundbased.NewSimulatorMessageRouter(participants)
	results := make([]int, n)
	var errGroup errgroup.Group
	for i := range n {
		errGroup.Go(func() error {
			results[i] = exampleBroadcastProtocol(router, ids[i], participants)
			return nil
		})
	}

	err = errGroup.Wait()
	require.NoError(t, err)
	router.Done()

	for i := 0; i < n-1; i++ {
		require.Equal(t, results[i], results[i+1])
	}
}
