package rb_test

import (
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/rb"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"testing"
	"time"
)

func Test_SimulatorEchoBroadcastP2P(t *testing.T) {
	const n = 3

	sessionId := "testSessionId"
	identities := make([]types.IdentityKey, n)
	for i := range identities {
		var err error
		identities[i], err = rb.NewAuthIdentity()
		require.NoError(t, err)
	}

	// every participant sends 1 message to every other, and receives one message from every other
	participantRunner := func(idIdx int) {
		me := identities[idIdx]
		coordinator, err := rb.DialCoordinatorSimulator(sessionId, identities[idIdx].(types.AuthKey), identities)
		auth := rb.NewSimulatorAuth(coordinator)
		echoBroadcast := rb.NewEchoBroadcast(auth)
		require.NoError(t, err)

		// send
		for _, them := range identities {
			if me.Equal(them) {
				continue
			}
			err = echoBroadcast.Send(them, []byte(fmt.Sprintf("%s -> %s", me.String(), them.String())))
			require.NoError(t, err)
		}

		// receive
		received := make(map[string][]byte)
		for i := 0; i < len(identities)-1; i++ {
			from, message, err := echoBroadcast.Receive()
			require.NoError(t, err)
			fmt.Printf("%s: Received '%s' from %s\n", me.String(), string(message), from.String())
			if _, ok := received[from.String()]; ok {
				require.Fail(t, "duplicated message from ", from.String())
			}
			received[from.String()] = message
		}

		// check
		require.Len(t, received, n-1)
		for _, id := range identities {
			if id.Equal(me) {
				continue
			}
			if _, ok := received[id.String()]; !ok {
				require.Fail(t, "no message from %s", id.String())
			}
		}
	}

	errChan := make(chan error)
	go func() {
		var group errgroup.Group
		for i := range n {
			group.Go(func() error {
				participantRunner(i)
				return nil
			})
		}
		errChan <- group.Wait()
	}()

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		require.Fail(t, "timeout")
	}
}

func Test_SimulatorEchoBroadcastBroadcast(t *testing.T) {
	const n = 5

	sessionId := "testSessionId"
	identities := make([]types.IdentityKey, n)
	for i := range identities {
		var err error
		identities[i], err = rb.NewAuthIdentity()
		require.NoError(t, err)
	}

	// every participant broadcasts 1 message, and receives one message from every other broadcast
	participantRunner := func(idIdx int) {
		me := identities[idIdx]
		coordinator, err := rb.DialCoordinatorSimulator(sessionId, identities[idIdx].(types.AuthKey), identities)
		auth := rb.NewSimulatorAuth(coordinator)
		echoBroadcast := rb.NewEchoBroadcast(auth)
		require.NoError(t, err)

		// send
		err = echoBroadcast.Broadcast([]byte(fmt.Sprintf("%s -> everyone", me.String())))
		require.NoError(t, err)

		// receive
		received := make(map[string][]byte)
		for i := 0; i < len(identities)-1; i++ {
			from, message, err := echoBroadcast.ReceiveBroadcast()
			require.NoError(t, err)
			fmt.Printf("%s: Received '%s' from %s\n", me.String(), string(message), from.String())
			if _, ok := received[from.String()]; ok {
				require.Fail(t, "duplicated message from ", from.String())
			}
			received[from.String()] = message
		}

		// check
		require.Len(t, received, n-1)
		for _, id := range identities {
			if id.Equal(me) {
				continue
			}
			if _, ok := received[id.String()]; !ok {
				require.Fail(t, "no message from %s", id.String())
			}
		}
	}

	errChan := make(chan error)
	go func() {
		var group errgroup.Group
		for i := range n {
			group.Go(func() error {
				participantRunner(i)
				return nil
			})
		}
		errChan <- group.Wait()
	}()

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		require.Fail(t, "timeout")
	}
}
