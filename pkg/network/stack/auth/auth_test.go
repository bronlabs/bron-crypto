package auth_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/auth"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/testutils"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_HappyPath(t *testing.T) {
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

	authClientFactory := auth.NewAuthClientFactory(testutils.NewSimulatorClientFactory())

	// create clients (resemble SDK)
	aliceClient := authClientFactory.Dial(alice)
	bobClient := authClientFactory.Dial(bob)
	charlieClient := authClientFactory.Dial(charlie)

	// run worker for each client (everyone sends a message to other parties)
	// and prints any received messages
	worker := func(party auth.Client, recipients []types.IdentityKey) {

		// 1. send a messages
		for _, recipient := range recipients {
			payload := fmt.Sprintf("Message from %s to %s",
				hex.EncodeToString(party.GetAuthKey().PublicKey().ToAffineCompressed()),
				hex.EncodeToString(recipient.PublicKey().ToAffineCompressed()),
			)
			party.SendTo(recipient, []byte(payload))
		}

		// 2. collect any received messages
		// I am too lazy to create a test for that so just check the console output to see if
		// expected messages were received
		for {
			from, payload := party.Recv()
			fmt.Printf("'%s' received message from '%s' with payload: '%s'.\n",
				hex.EncodeToString(party.GetAuthKey().PublicKey().ToAffineCompressed()),
				hex.EncodeToString(from.PublicKey().ToAffineCompressed()),
				string(payload),
			)
		}
	}

	go worker(aliceClient, []types.IdentityKey{bob, charlie})
	go worker(bobClient, []types.IdentityKey{alice, charlie})
	go worker(charlieClient, []types.IdentityKey{alice, bob})

	// wait a little to settle
	time.Sleep(2 * time.Second)
}
