package roundbased_test

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"math/rand/v2"
	"testing"
	"time"
)

type exampleRound1UnicastMessage struct {
	value int
}

func exampleUnicastProtocol(router roundbased.MessageRouter, party types.IdentityKey, participants datastructures.Set[types.IdentityKey]) int {
	round1 := roundbased.NewSimulatorRound[any, any, *exampleRound1UnicastMessage, any](router, 1, party)
	round2 := roundbased.NewSimulatorRound[any, any, any, *exampleRound1UnicastMessage](router, 2, party)

	// round 1
	myShare := 0
	output := hashmap.NewHashableHashMap[types.IdentityKey, *exampleRound1UnicastMessage]()
	for iter := participants.Iterator(); iter.HasNext(); {
		id := iter.Next()
		if id.Equal(party) {
			continue
		}

		theirShare := rand.N[int](500)
		myShare = myShare - theirShare
		output.Put(id, &exampleRound1UnicastMessage{value: theirShare})
	}
	err := round1.SendUnicast(output)
	if err != nil {
		panic(err)
	}

	// round 2
	input, err := round2.ReceiveUnicast()
	if err != nil {
		panic(err)
	}
	for iter := input.Iterator(); iter.HasNext(); {
		entry := iter.Next()
		m := entry.Value
		myShare = myShare + m.value
	}

	return myShare
}

func Test_Unicast(t *testing.T) {
	const n = 3

	ids, err := testutils.MakeDeterministicTestIdentities(n)
	require.NoError(t, err)
	participants := hashset.NewHashableHashSet(ids...)

	router := roundbased.NewSimulatorMessageRouter(participants)
	results := make([]int, n)
	var errGroup errgroup.Group
	for i := range n {
		errGroup.Go(func() error {
			results[i] = exampleUnicastProtocol(router, ids[i], participants)
			return nil
		})
	}

	time.Sleep(10 * time.Second)

	err = errGroup.Wait()
	require.NoError(t, err)
	router.Done()

	for i := 0; i < n; i++ {
		println(results[i])
	}
}
