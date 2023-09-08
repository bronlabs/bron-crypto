package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/base/protocols"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/dkg"

	"github.com/copperexchange/knox-primitives/pkg/base/integration/test_utils"

	"github.com/copperexchange/knox-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
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
