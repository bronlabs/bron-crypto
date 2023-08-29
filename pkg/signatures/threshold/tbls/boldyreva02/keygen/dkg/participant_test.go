package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/signatures/bls"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02/keygen/dkg"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/stretchr/testify/require"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := bls12381.NewG1()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha512.New512_256,
	}

	identities, err := test_utils.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)

	cohortConfig, err := test_utils_integration.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, 2, identities)
	require.NoError(t, err)
	uniqueSessionId := []byte("sid")

	aliceInG1, err := dkg.NewParticipant[bls.G1](uniqueSessionId, identities[0], cohortConfig, nil, crand.Reader)
	bobInG1, err := dkg.NewParticipant[bls.G1](uniqueSessionId, identities[1], cohortConfig, nil, crand.Reader)
	for _, party := range []*dkg.Participant[bls.G1]{aliceInG1, bobInG1} {
		require.NoError(t, err)
		require.NotNil(t, party)
	}
	require.NotEqual(t, aliceInG1.GetSharingId(), bobInG1.GetSharingId())
}
