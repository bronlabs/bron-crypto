package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/dkg"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/stretchr/testify/require"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	cipherSuite, err := testutils.MakeSignatureProtocol(curve, sha512.New512_256)
	require.NoError(t, err)

	threshold := 2

	identities, err := testutils.MakeTestIdentities(cipherSuite, threshold)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	nic := randomisedFischlin.Name

	uniqueSessionId := []byte("sid")
	alice, err := dkg.NewParticipant(uniqueSessionId, identities[0].(types.AuthKey), protocol, nic, nil, crand.Reader)
	bob, err := dkg.NewParticipant(uniqueSessionId, identities[1].(types.AuthKey), protocol, nic, nil, crand.Reader)
	for _, party := range []*dkg.Participant{alice, bob} {
		require.NoError(t, err)
		require.NotNil(t, party)
	}
	require.NotEqual(t, alice.SharingId(), bob.SharingId())
}
