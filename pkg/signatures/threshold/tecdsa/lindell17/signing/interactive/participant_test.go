package interactive_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/signing/interactive"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	cipherSuite := &integration.CipherSuite{
		Curve: curves.K256(),
		Hash:  sha256.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, 3)
	require.NoError(t, err)

	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocols.LINDELL17, identities, 2, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(cohortConfig, prng)
	require.NoError(t, err)

	aliceIdx := 0
	bobIdx := 1
	sessionId := []byte("DummySession")
	shard, _ := shards.Get(identities[aliceIdx])
	alice, err := interactive.NewPrimaryCosigner(identities[aliceIdx], identities[bobIdx], shard, cohortConfig, sessionId, nil, prng)
	require.NoError(t, err)
	require.NotNil(t, alice)
	shard, _ = shards.Get(identities[bobIdx])
	bob, err := interactive.NewSecondaryCosigner(identities[bobIdx], identities[aliceIdx], shard, cohortConfig, sessionId, nil, prng)
	require.NoError(t, err)
	require.NotNil(t, alice)

	require.NotEqual(t, alice.GetSharingId(), bob.GetSharingId())
}
