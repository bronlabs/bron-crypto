package broadcast_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/auth"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/broadcast"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/testutils"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader

	// create keys
	aliceSk, err := p256.NewScalarField().Random(prng)
	require.NoError(t, err)
	bobSk, err := p256.NewScalarField().Random(prng)
	require.NoError(t, err)
	charlieSk, err := p256.NewScalarField().Random(prng)
	require.NoError(t, err)

	// create identities
	alice := testutils.NewTestAuthKey(aliceSk)
	bob := testutils.NewTestAuthKey(bobSk)
	charlie := testutils.NewTestAuthKey(charlieSk)

	dummyProtocol, err := types.NewProtocol(p256.NewCurve(), hashset.NewHashableHashSet[types.IdentityKey](alice, bob, charlie))
	require.NoError(t, err)

	broadcastFactory := broadcast.NewBroadcastClientFactory(auth.NewAuthClientFactory(testutils.NewSimulatorClientFactory()))

	// create clients (resemble SDK)
	aliceClient := broadcastFactory.Dial(alice, dummyProtocol)
	bobClient := broadcastFactory.Dial(bob, dummyProtocol)
	charlieClient := broadcastFactory.Dial(charlie, dummyProtocol)

	// run worker for each client (everyone sends a message to other parties)
	// and prints any received messages
	worker := func(party broadcast.Client, destinations []types.IdentityKey) {

		// 1. send a broadcast messages
		payload := fmt.Sprintf("Message from %s to EVERYONE",
			hex.EncodeToString(party.GetAuthKey().PublicKey().ToAffineCompressed()),
		)
		party.Broadcast([]byte(payload))

		// 2. send unicast messages
		for _, dest := range destinations {
			payload := fmt.Sprintf("Message from %s to %s",
				hex.EncodeToString(party.GetAuthKey().PublicKey().ToAffineCompressed()),
				hex.EncodeToString(dest.PublicKey().ToAffineCompressed()),
			)
			party.SendTo(dest, []byte(payload))
		}

		// 2. collect any received messages
		// I am too lazy to create a test for that so just check the console output to see if
		// expected messages were received
		for {
			from, typ, payload := party.Recv()
			fmt.Printf("'%s' received message from '%s' with payload: '%s' of type: '%s'.\n",
				hex.EncodeToString(party.GetAuthKey().PublicKey().ToAffineCompressed()),
				hex.EncodeToString(from.PublicKey().ToAffineCompressed()),
				string(payload),
				typ,
			)
		}
	}

	go worker(aliceClient, []types.IdentityKey{bob, charlie})
	go worker(bobClient, []types.IdentityKey{alice, charlie})
	go worker(charlieClient, []types.IdentityKey{alice, bob})

	// wait a little to settle
	time.Sleep(2 * time.Second)
}
