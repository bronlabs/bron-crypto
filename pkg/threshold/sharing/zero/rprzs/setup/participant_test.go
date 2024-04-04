package setup_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs/setup"
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

	protocol, err := testutils.MakeProtocol(curve, identities)
	require.NoError(t, err)

	alice, err := setup.NewParticipant([]byte("test"), aliceIdentityKey.(types.AuthKey), protocol, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := setup.NewParticipant([]byte("test"), bobIdentityKey.(types.AuthKey), protocol, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, bob)
	for _, party := range []*setup.Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, party.IdentitySpace.Size(), 2)
		require.Len(t, party.SortedParticipants, 2)
	}
	require.NotEqualValues(t, alice.IdentityKey(), bob.IdentityKey())
}
