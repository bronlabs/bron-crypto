package pedersen_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/base/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/base/protocols"
	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/threshold/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/knox-primitives/pkg/threshold/dkg/pedersen/test_utils"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha3.New256,
	}

	var identities []integration.IdentityKey
	var cohortConfig *integration.CohortConfig
	var uniqueSessionId []byte
	var participants []*pedersen.Participant
	var err error

	internal.RunMeasurement(500, "pedersen_round1", func(i int) {
		identities, err = test_utils_integration.MakeIdentities(cipherSuite, 3)
		require.NoError(t, err)
		cohortConfig, err = test_utils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_test_utils.ProduceSharedRandomValue(cipherSuite.Curve, identities, crand.Reader)
		require.NoError(t, err)
		participants, err = test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
		require.NoError(t, err)
	}, func() {
		test_utils.DoDkgRound1(participants, nil)
	})
}

func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha3.New256,
	}

	var identities []integration.IdentityKey
	var cohortConfig *integration.CohortConfig
	var uniqueSessionId []byte
	var participants []*pedersen.Participant
	var err error
	var r1OutsB []*pedersen.Round1Broadcast
	var r1OutsU []map[helper_types.IdentityHash]*pedersen.Round1P2P
	var r2InsB []map[helper_types.IdentityHash]*pedersen.Round1Broadcast
	var r2InsU []map[helper_types.IdentityHash]*pedersen.Round1P2P

	internal.RunMeasurement(500, "pedersen_round2", func(i int) {
		identities, err = test_utils_integration.MakeIdentities(cipherSuite, 3)
		require.NoError(t, err)
		cohortConfig, err = test_utils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_test_utils.ProduceSharedRandomValue(cipherSuite.Curve, identities, crand.Reader)
		require.NoError(t, err)
		participants, err = test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
		require.NoError(t, err)
		r1OutsB, r1OutsU, err = test_utils.DoDkgRound1(participants, nil)
		require.NoError(t, err)
		r2InsB, r2InsU = test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	}, func() {
		test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	})
}
