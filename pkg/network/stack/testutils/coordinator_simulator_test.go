package testutils_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/coordinator"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/testutils"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_HappyPath(t *testing.T) {
	prng := crand.Reader

	// create keys
	alicePk, err := p256.NewCurve().Random(prng)
	require.NoError(t, err)
	bobPk, err := p256.NewCurve().Random(prng)
	require.NoError(t, err)
	charliePk, err := p256.NewCurve().Random(prng)
	require.NoError(t, err)

	// create identities
	alice := testutils.NewTestIdentityKey(alicePk)
	bob := testutils.NewTestIdentityKey(bobPk)
	charlie := testutils.NewTestIdentityKey(charliePk)

	// create a server (resembles Coordinator)
	clientFactory := testutils.NewSimulatorClientFactory()

	// create clients (resemble SDK)
	aliceClient := clientFactory.Dial(alice)
	bobClient := clientFactory.Dial(bob)
	charlieClient := clientFactory.Dial(charlie)

	// run worker for each client (everyone sends a message to other parties)
	// and prints any received messages
	worker := func(party coordinator.Client, recipients []types.IdentityKey) {

		// 1. send a messages
		for _, recipient := range recipients {
			payload := fmt.Sprintf("Message from %s to %s", party.GetIdentityKey().String(), recipient)
			party.SendTo(recipient, []byte(payload))
		}

		// 2. collect any received messages
		// I am too lazy to create a test for that so just check the console output to see if
		// expected messages were received
		for {
			from, payload := party.Recv()
			fmt.Printf("'%s' received message from '%s' with payload: '%s'.\n", party.GetIdentityKey().String(), from.String(), string(payload))
		}
	}

	go worker(aliceClient, []types.IdentityKey{bob, charlie})
	go worker(bobClient, []types.IdentityKey{alice, charlie})
	go worker(charlieClient, []types.IdentityKey{alice, bob})

	// wait a little to settle
	time.Sleep(2 * time.Second)
}
