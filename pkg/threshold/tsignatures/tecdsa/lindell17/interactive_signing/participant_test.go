package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/interactive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha256.New,
	}
	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)

	cohortConfig, err := testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, 2, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(cohortConfig, prng)
	require.NoError(t, err)

	aliceIdx := 0
	bobIdx := 1
	sessionId := []byte("DummySession")
	alice, err := interactive_signing.NewPrimaryCosigner(identities[aliceIdx], identities[bobIdx], shards[identities[aliceIdx].Hash()], cohortConfig, sessionId, nil, prng)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bob, err := interactive_signing.NewSecondaryCosigner(identities[bobIdx], identities[aliceIdx], shards[identities[bobIdx].Hash()], cohortConfig, sessionId, nil, prng)
	require.NoError(t, err)
	require.NotNil(t, alice)

	require.NotEqual(t, alice.GetSharingId(), bob.GetSharingId())
}
