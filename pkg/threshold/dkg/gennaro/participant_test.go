package gennaro_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha512.New512_256,
	}

	identities, err := testutils.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.FROST,
			Threshold:            2,
			TotalParties:         2,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	alice, err := gennaro.NewParticipant([]byte("sid"), identities[0].(integration.AuthKey), cohortConfig, randomisedFischlin.Name, crand.Reader, nil)
	require.NoError(t, err)
	bob, err := gennaro.NewParticipant([]byte("sid"), identities[1].(integration.AuthKey), cohortConfig, randomisedFischlin.Name, crand.Reader, nil)
	require.NoError(t, err)
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
	require.True(t, alice.H.Equal(bob.H))
}
