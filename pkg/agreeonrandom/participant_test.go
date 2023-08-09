package agreeonrandom

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := curves.ED25519()
	cipherSuite := &integration.CipherSuite{Curve: curve, Hash: sha3.New256}
	identities, err := test_utils.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	var sharedSeed zero.Seed
	hashed, err := hashing.Hash(sha3.New256, []byte("pepsi > coke"))
	require.NoError(t, err)
	copy(sharedSeed[:], hashed)

	alice, err := NewParticipant(curve, aliceIdentityKey, identities, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := NewParticipant(curve, bobIdentityKey, identities, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.NotNil(t, party.state)
	}
	require.Equal(t, alice.state.transcript.ExtractBytes("test", 32), bob.state.transcript.ExtractBytes("test", 32))
}
