package sample

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	csprng "github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.New()
	cipherSuite := &integration.CipherSuite{Curve: curve, Hash: sha3.New256}
	identities, err := testutils.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	var sharedSeed przs.Seed
	hashed, err := hashing.Hash(sha3.New256, []byte("pepsi > coke"))
	require.NoError(t, err)
	copy(sharedSeed[:], hashed)

	aliceSeeds := przs.PairwiseSeeds{bobIdentityKey.Hash(): sharedSeed}
	bobSeeds := przs.PairwiseSeeds{aliceIdentityKey.Hash(): sharedSeed}
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
	}

	prng, err := csprng.NewChachaPRNG(nil, nil)
	require.NoError(t, err)

	alice, err := NewParticipant(cohortConfig, uniqueSessionId, aliceIdentityKey, aliceSeeds, hashset.NewHashSet(identities), prng)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := NewParticipant(cohortConfig, uniqueSessionId, bobIdentityKey, bobSeeds, hashset.NewHashSet(identities), prng)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.Len(t, party.IdentityKeyToSharingId, 2)
		require.Equal(t, party.PresentParticipants.Len(), 2)
	}
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
}
