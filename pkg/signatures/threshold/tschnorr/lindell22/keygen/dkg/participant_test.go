package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/keygen/dkg"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/stretchr/testify/require"
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
			Name:                 protocols.LINDELL22,
			Threshold:            2,
			TotalParties:         2,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	uniqueSessionId := []byte("sid")
	alice, err := dkg.NewParticipant(uniqueSessionId, identities[0], cohortConfig, nil, crand.Reader)
	bob, err := dkg.NewParticipant(uniqueSessionId, identities[1], cohortConfig, nil, crand.Reader)
	for _, party := range []*dkg.Participant{alice, bob} {
		require.NoError(t, err)
		require.NotNil(t, party)
	}
	require.NotEqual(t, alice.GetSharingId(), bob.GetSharingId())
}
