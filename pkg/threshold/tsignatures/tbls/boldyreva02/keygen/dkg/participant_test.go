package dkg_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/dkg"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/stretchr/testify/require"
)

func Test_CanInitialize(t *testing.T) {
	t.Parallel()
	cn := randomisedFischlin.Name
	curve := bls12381.NewG1()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdProtocol(curve, identities, 2)
	require.NoError(t, err)
	uniqueSessionId := []byte("sid")

	aliceInG1, err := dkg.NewParticipant[bls12381.G1](uniqueSessionId, identities[0].(types.AuthKey), protocol, cn, nil, crand.Reader)
	bobInG1, err := dkg.NewParticipant[bls12381.G1](uniqueSessionId, identities[1].(types.AuthKey), protocol, cn, nil, crand.Reader)
	for _, party := range []*dkg.Participant[bls12381.G1]{aliceInG1, bobInG1} {
		require.NoError(t, err)
		require.NotNil(t, party)
	}
	require.NotEqual(t, aliceInG1.SharingId(), bobInG1.SharingId())
}
