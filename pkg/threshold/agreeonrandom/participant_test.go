package agreeonrandom

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/hashing"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/zero/przs"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.New()
	cipherSuite := &integration.CipherSuite{Curve: curve, Hash: sha3.New256}
	identities, err := test_utils.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	var sharedSeed przs.Seed
	hashed, err := hashing.Hash(sha3.New256, []byte("pepsi > coke"))
	require.NoError(t, err)
	copy(sharedSeed[:], hashed)

	alice, err := NewParticipant(curve, aliceIdentityKey, hashset.NewHashSet(identities), nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := NewParticipant(curve, bobIdentityKey, hashset.NewHashSet(identities), nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.NotNil(t, party.state)
	}
	aliceExtractedBytes, _ := alice.state.transcript.ExtractBytes("test", 32)
	bobExtractedBytes, _ := bob.state.transcript.ExtractBytes("test", 32)
	require.Equal(t, aliceExtractedBytes, bobExtractedBytes)
}
