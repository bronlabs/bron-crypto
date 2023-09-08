package gennaro_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton/pkg/threshold/dkg/gennaro"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.New()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha512.New512_256,
	}

	identities, err := testutils.MakeIdentities(cipherSuite, 2)
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
