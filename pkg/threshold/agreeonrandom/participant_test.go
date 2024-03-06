package agreeonrandom

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	hash := sha3.New256
	cipherSuite, err := testutils.MakeSignatureProtocol(curve, hash)
	require.NoError(t, err)
	identities, err := testutils.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	var sharedSeed przs.Seed
	hashed, err := hashing.HashChain(sha3.New256, []byte("pepsi > coke"))
	require.NoError(t, err)
	copy(sharedSeed[:], hashed)

	protocol, err := testutils.MakeMPCProtocol(curve, identities)
	require.NoError(t, err)

	alice, err := NewParticipant(aliceIdentityKey.(types.AuthKey), protocol, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := NewParticipant(bobIdentityKey.(types.AuthKey), protocol, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*Participant{alice, bob} {
		require.NoError(t, err)
		require.NoError(t, party.InRound(1))
		require.NotNil(t, party.state)
	}
	aliceExtractedBytes, _ := alice.Transcript().ExtractBytes("test", 32)
	bobExtractedBytes, _ := bob.Transcript().ExtractBytes("test", 32)
	require.Equal(t, aliceExtractedBytes, bobExtractedBytes)
}
