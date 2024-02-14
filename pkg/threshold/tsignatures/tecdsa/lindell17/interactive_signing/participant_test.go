package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/interactive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	cn := randomisedFischlin.Name

	curve := k256.NewCurve()
	hash := sha256.New
	cipherSuite, err := testutils.MakeSignatureProtocol(curve, hash)
	require.NoError(t, err)
	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)

	aliceIdx := 0
	bobIdx := 1
	sessionId := []byte("DummySession")
	aliceShard, exists := shards.Get(identities[aliceIdx])
	require.True(t, exists)
	alice, err := interactive_signing.NewPrimaryCosigner(sessionId, identities[aliceIdx].(types.AuthKey), identities[bobIdx], aliceShard, protocol, cn, nil, prng)
	require.NoError(t, err)
	require.NotNil(t, alice)
	bobShard, exists := shards.Get(identities[bobIdx])
	require.True(t, exists)
	bob, err := interactive_signing.NewSecondaryCosigner(sessionId, identities[bobIdx].(types.AuthKey), identities[aliceIdx], bobShard, protocol, cn, nil, prng)
	require.NoError(t, err)
	require.NotNil(t, alice)

	require.NotEqual(t, alice.SharingId(), bob.SharingId())
}
