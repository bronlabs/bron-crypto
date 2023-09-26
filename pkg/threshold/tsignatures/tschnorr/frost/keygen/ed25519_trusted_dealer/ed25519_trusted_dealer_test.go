package trusted_dealer_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	trusted_dealer "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/keygen/ed25519_trusted_dealer"
	"github.com/stretchr/testify/require"
)

func Test_happyPath(t *testing.T) {
	t.Parallel()
	curve := edwards25519.New()
	h := sha512.New

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	aliceIdentityKey, err := testutils.MakeTestIdentity(cipherSuite, nil)
	require.NoError(t, err)
	bobIdentityKey, err := testutils.MakeTestIdentity(cipherSuite, nil)
	require.NoError(t, err)
	charlieIdentityKey, err := testutils.MakeTestIdentity(cipherSuite, nil)
	require.NoError(t, err)

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet([]integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey}),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.FROST,
			Threshold:            2,
			TotalParties:         3,
			SignatureAggregators: hashset.NewHashSet([]integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey}),
		},
	}

	signingKeyShares, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, signingKeyShares)
	require.Len(t, signingKeyShares, cohortConfig.Protocol.TotalParties)

	for _, signingKeyShare := range signingKeyShares {
		err = signingKeyShare.Validate()
		require.NoError(t, err)
	}
}
