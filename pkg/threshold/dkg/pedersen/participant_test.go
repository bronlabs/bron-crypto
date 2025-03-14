package pedersen_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	randomisedFischlin "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/pedersen"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	threshold := 2
	hash := sha3.New256
	cipherSuite, err := testutils.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := testutils.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)
	aliceIdentityKey, bobIdentityKey := identities[0], identities[1]

	protocol, err := testutils.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	alice, err := pedersen.NewParticipant([]byte("test"), aliceIdentityKey.(types.AuthKey), protocol, randomisedFischlin.Name, nil, crand.Reader)
	require.NoError(t, err)
	bob, err := pedersen.NewParticipant([]byte("test"), bobIdentityKey.(types.AuthKey), protocol, randomisedFischlin.Name, nil, crand.Reader)
	require.NoError(t, err)
	for _, party := range []*pedersen.Participant{alice, bob} {
		require.NoError(t, err)
		require.Equal(t, 2, party.SharingConfig.Size())
	}
	require.NotEqual(t, alice.SharingId(), bob.SharingId())
}
