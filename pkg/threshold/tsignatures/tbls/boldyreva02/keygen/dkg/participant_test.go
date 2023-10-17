package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"

	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/dkg"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/stretchr/testify/require"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	curve := bls12381.NewG1()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha512.New512_256,
	}

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)

	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, 2, identities)
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
