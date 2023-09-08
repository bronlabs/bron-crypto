package signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/curves/k256"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/lindell17/signing"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha256.New,
	}
	identities, err := testutils.MakeIdentities(cipherSuite, 3)
	require.NoError(t, err)

	cohortConfig, err := testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, 2, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(cohortConfig, prng)
	require.NoError(t, err)

	aliceIdx := 0
	bobIdx := 1
	sessionId := []byte("DummySession")
	alice, err := signing.NewPrimaryCosigner(identities[aliceIdx], identities[bobIdx], shards[identities[aliceIdx].Hash()], cohortConfig, sessionId, nil, prng)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := signing.NewSecondaryCosigner(identities[bobIdx], identities[aliceIdx], shards[identities[bobIdx].Hash()], cohortConfig, sessionId, nil, prng)
	require.NoError(t, err)
	require.NotNil(t, alice)

	require.NotEqual(t, alice.GetSharingId(), bob.GetSharingId())
}
