package setup

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := curves.ED25519()
	cipherSuite := &integration.CipherSuite{Curve: curve, Hash: sha3.New256}
	identities, err := test_utils.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	alice, err := NewParticipant(curve, []byte("test"), aliceIdentityKey, identities, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := NewParticipant(curve, []byte("test"), bobIdentityKey, identities, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.IdentityKeyToSharingId, 2)
		require.Len(t, party.Participants, 2)
		require.NotNil(t, party.state)
		require.NotNil(t, party.state.transcript)
		require.NotNil(t, party.state.receivedSeeds)
		require.NotNil(t, party.state.sentSeeds)
	}
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
}
