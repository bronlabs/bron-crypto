package setup

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	cipherSuite := &integration.CipherSuite{Curve: curve, Hash: sha3.New256}
	identities, err := testutils.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	alice, err := NewParticipant(curve, []byte("test"), aliceIdentityKey.(integration.AuthKey), hashset.NewHashSet(identities), nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := NewParticipant(curve, []byte("test"), bobIdentityKey.(integration.AuthKey), hashset.NewHashSet(identities), nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.IdentityKeyToSharingId, 2)
		require.Len(t, party.SortedParticipants, 2)
		require.NotNil(t, party.state)
		require.NotNil(t, party.state.transcript)
		require.NotNil(t, party.state.receivedSeeds)
		require.NotNil(t, party.state.sentSeeds)
	}
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
}
