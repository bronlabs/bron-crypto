package sample_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	agreeonrandom_testutils "github.com/bronlabs/bron-crypto/pkg/threshold/agreeonrandom/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/sample"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	h := sha512.New512_256
	cipherSuite, err := testutils.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	threshold := 2
	identities, err := testutils.MakeTestIdentities(cipherSuite, threshold)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	var sharedSeed rprzs.Seed
	hashed, err := hashing.Hash(sha3.New256, []byte("pepsi > coke"))
	require.NoError(t, err)
	copy(sharedSeed[:], hashed)

	aliceSeeds := hashmap.NewHashableHashMap[types.IdentityKey, [32]byte]()
	aliceSeeds.Put(bobIdentityKey, sharedSeed)
	bobSeeds := hashmap.NewHashableHashMap[types.IdentityKey, [32]byte]()
	bobSeeds.Put(aliceIdentityKey, sharedSeed)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	prng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)

	presentParties := protocol.Participants()

	alice, err := sample.NewParticipant(uniqueSessionId, aliceIdentityKey.(types.AuthKey), aliceSeeds, protocol, presentParties, prng)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := sample.NewParticipant(uniqueSessionId, bobIdentityKey.(types.AuthKey), bobSeeds, protocol, presentParties, prng)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*sample.Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, 2, party.IdentitySpace.Size())
		require.Equal(t, 2, party.PresentParticipants.Size())
	}
	require.NotEqualValues(t, alice.IdentityKey(), bob.IdentityKey())
}
