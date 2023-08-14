package sample

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.New()
	cipherSuite := &integration.CipherSuite{Curve: curve, Hash: sha3.New256}
	identities, err := test_utils.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	var sharedSeed zero.Seed
	hashed, err := hashing.Hash(sha3.New256, []byte("pepsi > coke"))
	require.NoError(t, err)
	copy(sharedSeed[:], hashed)

	aliceSeeds := zero.PairwiseSeeds{bobIdentityKey.Hash(): sharedSeed}
	bobSeeds := zero.PairwiseSeeds{aliceIdentityKey.Hash(): sharedSeed}
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: identities,
	}

	alice, err := NewParticipant(cohortConfig, uniqueSessionId, aliceIdentityKey, aliceSeeds, identities)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := NewParticipant(cohortConfig, uniqueSessionId, bobIdentityKey, bobSeeds, identities)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.round, 1)
		require.Len(t, party.IdentityKeyToSharingId, 2)
		require.Len(t, party.PresentParticipants, 2)
	}
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
}
