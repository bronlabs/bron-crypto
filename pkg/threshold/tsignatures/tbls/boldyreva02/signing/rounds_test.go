package signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/protocols"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton/pkg/signatures/bls"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/trusted_dealer"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tbls/boldyreva02/signing/aggregation"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tbls/boldyreva02/testutils"
)

func roundtrip[K bls.KeySubGroup, S bls.SignatureSubGroup](t *testing.T, threshold, n int) {
	t.Helper()
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	pointInK := new(K)
	keysSubGroup := (*pointInK).Curve()

	cipherSuite := &integration.CipherSuite{
		Curve: keysSubGroup,
		Hash:  hashFunc,
	}

	identities, err := integration_testutils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen[K](cohort, crand.Reader)
	require.NoError(t, err)

	publicKeyShares := shards[identities[0].Hash()].PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := testutils.MakeSigningParticipants[K, S](sid, cohort, identities, shards)
	require.NoError(t, err)

	partialSignatures, err := testutils.ProducePartialSignature(participants, message)
	require.NoError(t, err)

	aggregatorInput := testutils.MapPartialSignatures(identities, partialSignatures)

	agg, err := aggregation.NewAggregator[K, S](shards[identities[0].Hash()].PublicKeyShares, cohort)
	require.NoError(t, err)

	signature, err := agg.Aggregate(aggregatorInput, message)
	require.NoError(t, err)

	err = bls.Verify(publicKey, signature, message, nil, bls.Basic)
	require.Error(t, err)
}

func TestHappyPath(t *testing.T) {
	t.Parallel()

	for _, config := range []struct {
		threshold int
		total     int
	}{
		{2, 2},
		{2, 3},
		{3, 3},
	} {
		boundedConfig := config
		t.Run(fmt.Sprintf("running happy path for t=%d and n=%d", boundedConfig.threshold, boundedConfig.total), func(t *testing.T) {
			t.Parallel()
			t.Run("short keys", func(t *testing.T) {
				t.Parallel()
				roundtrip[bls.G1, bls.G2](t, boundedConfig.threshold, boundedConfig.total)
			})
			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				roundtrip[bls.G2, bls.G1](t, boundedConfig.threshold, boundedConfig.total)
			})
		})
	}
}
