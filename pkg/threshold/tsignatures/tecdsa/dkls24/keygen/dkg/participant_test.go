package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/keygen/dkg"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	hash := sha256.New
	cipherSuite, err := testutils.MakeSignatureProtocol(curve, hash)
	require.NoError(t, err)
	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)

	cn := randomisedFischlin.Name

	protocol, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(t, err)

	sid, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)
	alice, err := dkg.NewParticipant(sid, identities[0].(types.AuthKey), protocol, cn, crand.Reader, nil)
	require.NoError(t, err)
	bob, err := dkg.NewParticipant(sid, identities[1].(types.AuthKey), protocol, cn, crand.Reader, nil)
	for _, party := range []*dkg.Participant{alice, bob} {
		require.NoError(t, err)
		require.NotNil(t, party)
	}
	require.NotEqual(t, alice.SharingId(), bob.SharingId())
}
