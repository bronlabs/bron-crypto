package pedersen_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen/testutils"
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
		identities, err = testutils_integration.MakeIdentities(cipherSuite, 3)
		require.NoError(t, err)
		cohortConfig, err = testutils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.ProduceSharedRandomValue(cipherSuite.Curve, identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
		require.NoError(t, err)
	}, func() {
		testutils.DoDkgRound1(participants, nil)
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
	var r1OutsU []map[types.IdentityHash]*pedersen.Round1P2P
	var r2InsB []map[types.IdentityHash]*pedersen.Round1Broadcast
	var r2InsU []map[types.IdentityHash]*pedersen.Round1P2P

	internal.RunMeasurement(500, "pedersen_round2", func(i int) {
		identities, err = testutils_integration.MakeIdentities(cipherSuite, 3)
		require.NoError(t, err)
		cohortConfig, err = testutils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.ProduceSharedRandomValue(cipherSuite.Curve, identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
		require.NoError(t, err)
		r1OutsB, r1OutsU, err = testutils.DoDkgRound1(participants, nil)
		require.NoError(t, err)
		r2InsB, r2InsU = testutils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	}, func() {
		testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	})
}
