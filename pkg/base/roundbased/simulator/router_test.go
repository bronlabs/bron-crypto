package simulator_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased/simulator"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
)

func Test_SimpleRouterBroadcast(t *testing.T) {
	identities, err := testutils.MakeDeterministicTestIdentities(3)
	require.NoError(t, err)

	router := simulator.NewSimpleMessageRouter(hashset.NewHashableHashSet(identities...))
	worker := func(me types.IdentityKey) {
		r1b := roundbased.NewBroadcastRound[string](me, 1, router)
		r1b.BroadcastOut() <- fmt.Sprintf("FROM[%s]", me)

		received := <-r1b.BroadcastIn()
		for iter := received.Iterator(); iter.HasNext(); {
			e := iter.Next()
			fmt.Printf("Received %s from %s\n", e.Value, e.Key.String())
		}
	}

	errChan := make(chan error)
	go func() {
		var grp errgroup.Group
		for _, id := range identities {
			grp.Go(func() error {
				worker(id)
				return nil
			})
		}
		errChan <- grp.Wait()
	}()

	select {
	case err = <-errChan:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		require.Fail(t, "no response")
	}
}

func Test_SimpleRouterUnicast(t *testing.T) {
	identities, err := testutils.MakeDeterministicTestIdentities(3)
	require.NoError(t, err)

	router := simulator.NewSimpleMessageRouter(hashset.NewHashableHashSet(identities...))
	worker := func(me types.IdentityKey) {
		r1b := roundbased.NewUnicastRound[string](me, 1, router)
		sent := hashmap.NewHashableHashMap[types.IdentityKey, string]()
		for _, party := range identities {
			if party.Equal(me) {
				continue
			}
			sent.Put(party, fmt.Sprintf("[FROM:%s -> TO:%s]", me.String(), party.String()))
		}
		r1b.UnicastOut() <- sent

		received := <-r1b.UnicastIn()
		for iter := received.Iterator(); iter.HasNext(); {
			e := iter.Next()
			fmt.Printf("%s -> %s: Received %s\n", e.Key.String(), me.String(), e.Value)
		}
	}

	errChan := make(chan error)
	go func() {
		var grp errgroup.Group
		for _, id := range identities {
			grp.Go(func() error {
				worker(id)
				return nil
			})
		}
		errChan <- grp.Wait()
	}()

	select {
	case err = <-errChan:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		require.Fail(t, "no response")
	}
}

func Test_EchoBroadcastRouterBroadcast(t *testing.T) {
	identities, err := testutils.MakeDeterministicTestIdentities(3)
	require.NoError(t, err)

	router := simulator.NewEchoBroadcastMessageRouter(hashset.NewHashableHashSet(identities...))
	worker := func(me types.IdentityKey) {
		r1b := roundbased.NewBroadcastRound[string](me, 1, router)
		r1b.BroadcastOut() <- fmt.Sprintf("FROM[%s]", me)

		received := <-r1b.BroadcastIn()
		for iter := received.Iterator(); iter.HasNext(); {
			e := iter.Next()
			fmt.Printf("Received %s from %s\n", e.Value, e.Key.String())
		}
	}

	errChan := make(chan error)
	go func() {
		var grp errgroup.Group
		for _, id := range identities {
			grp.Go(func() error {
				worker(id)
				return nil
			})
		}
		errChan <- grp.Wait()
	}()

	select {
	case err = <-errChan:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		require.Fail(t, "no response")
	}
}

func Test_EchoBroadcastRouterUnicast(t *testing.T) {
	identities, err := testutils.MakeDeterministicTestIdentities(3)
	require.NoError(t, err)

	router := simulator.NewEchoBroadcastMessageRouter(hashset.NewHashableHashSet(identities...))
	worker := func(me types.IdentityKey) {
		r1b := roundbased.NewUnicastRound[string](me, 1, router)
		sent := hashmap.NewHashableHashMap[types.IdentityKey, string]()
		for _, party := range identities {
			if party.Equal(me) {
				continue
			}
			sent.Put(party, fmt.Sprintf("[FROM:%s -> TO:%s]", me.String(), party.String()))
		}
		r1b.UnicastOut() <- sent

		received := <-r1b.UnicastIn()
		for iter := received.Iterator(); iter.HasNext(); {
			e := iter.Next()
			fmt.Printf("%s -> %s: Received %s\n", e.Key.String(), me.String(), e.Value)
		}
	}

	errChan := make(chan error)
	go func() {
		var grp errgroup.Group
		for _, id := range identities {
			grp.Go(func() error {
				worker(id)
				return nil
			})
		}
		errChan <- grp.Wait()
	}()

	select {
	case err = <-errChan:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		require.Fail(t, "no response")
	}
}
