package gennaro_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/base/protocols"
	"github.com/copperexchange/knox-primitives/pkg/threshold/dkg/gennaro"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.New()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha512.New512_256,
	}

	identities, err := test_utils.MakeIdentities(cipherSuite, 2)
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
	alice, err := gennaro.NewParticipant([]byte("sid"), identities[0], cohortConfig, crand.Reader, nil)
	require.NoError(t, err)
	bob, err := gennaro.NewParticipant([]byte("sid"), identities[1], cohortConfig, crand.Reader, nil)
	require.NoError(t, err)
	require.NotEqual(t, alice.MySharingId, bob.MySharingId)
	require.True(t, alice.H.Equal(bob.H))
}
