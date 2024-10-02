package round_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/auth"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/broadcast"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/round"
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

	roundFactory := round.NewRoundClientFactory(broadcast.NewBroadcastClientFactory(auth.NewAuthClientFactory(testutils.NewSimulatorClientFactory())))

	// create clients (resemble SDK)
	aliceClient := roundFactory.Dial(alice, dummyProtocol)
	bobClient := roundFactory.Dial(bob, dummyProtocol)
	charlieClient := roundFactory.Dial(charlie, dummyProtocol)

	// run worker for each client (everyone sends a message to other parties)
	// and prints any received messages
	worker := func(party round.Client, destinations []types.IdentityKey) {
		r1b := []byte(fmt.Sprintf("Broadcast Message from %s to EVERYONE",
			hex.EncodeToString(party.GetAuthKey().PublicKey().ToAffineCompressed()),
		))
		r1u := hashmap.NewHashableHashMap[types.IdentityKey, []byte]()
		for _, dest := range destinations {
			payload := []byte(fmt.Sprintf("P2P Message from %s to %s",
				hex.EncodeToString(party.GetAuthKey().PublicKey().ToAffineCompressed()),
				hex.EncodeToString(dest.PublicKey().ToAffineCompressed()),
			))
			r1u.Put(dest, payload)
		}

		// send round 1
		party.Send("R1", r1b, r1u)
		r2b, r2u := party.Receive("R1", destinations, destinations)

		if party == aliceClient {
			for from, payload := range r2b.Iter() {
				fmt.Printf("B %s<-%s '%s'\n", hex.EncodeToString(party.GetAuthKey().PublicKey().ToAffineCompressed()), hex.EncodeToString(from.PublicKey().ToAffineCompressed()), string(payload))
			}
			for from, payload := range r2u.Iter() {
				fmt.Printf("U %s<-%s '%s'\n", hex.EncodeToString(party.GetAuthKey().PublicKey().ToAffineCompressed()), hex.EncodeToString(from.PublicKey().ToAffineCompressed()), string(payload))
			}
		}
	}

	go worker(aliceClient, []types.IdentityKey{bob, charlie})
	go worker(bobClient, []types.IdentityKey{alice, charlie})
	go worker(charlieClient, []types.IdentityKey{alice, bob})

	// wait a little to settle
	time.Sleep(2 * time.Second)
}
