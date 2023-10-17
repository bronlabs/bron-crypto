package gennaro_test

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
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro/testutils"
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
	var participants []*gennaro.Participant
	var err error

	internal.RunMeasurement(500, "gennaro_round1", func(i int) {
		identities, err = integration_testutils.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		cohortConfig, err = integration_testutils.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve, identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
		require.NoError(t, err)
	}, func() {
		testutils.DoDkgRound1(participants)
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
	var participants []*gennaro.Participant
	var err error
	var r1OutsB []*gennaro.Round1Broadcast
	var r1OutsU []map[types.IdentityHash]*gennaro.Round1P2P

	internal.RunMeasurement(500, "gennaro_round2", func(i int) {
		identities, err = integration_testutils.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		cohortConfig, err = integration_testutils.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve, identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
		require.NoError(t, err)
		r1OutsB, r1OutsU, err = testutils.DoDkgRound1(participants)
		require.NoError(t, err)
	}, func() {
		integration_testutils.MapO2I(participants, r1OutsB, r1OutsU)
	})
}

func Test_MeasureConstantTime_round3(t *testing.T) {
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
	var participants []*gennaro.Participant
	var err error
	var r1OutsB []*gennaro.Round1Broadcast
	var r1OutsU []map[types.IdentityHash]*gennaro.Round1P2P
	var r2InsB []map[types.IdentityHash]*gennaro.Round1Broadcast
	var r2InsU []map[types.IdentityHash]*gennaro.Round1P2P
	var r2Outs []*gennaro.Round2Broadcast
	var r3Ins []map[types.IdentityHash]*gennaro.Round2Broadcast

	internal.RunMeasurement(500, "gennaro_round3", func(i int) {
		identities, err = integration_testutils.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		cohortConfig, err = integration_testutils.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve, identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
		require.NoError(t, err)
		r1OutsB, r1OutsU, err = testutils.DoDkgRound1(participants)
		require.NoError(t, err)
		r2InsB, r2InsU = integration_testutils.MapO2I(participants, r1OutsB, r1OutsU)
		r2Outs, err = testutils.DoDkgRound2(participants, r2InsB, r2InsU)
		require.NoError(t, err)
		r3Ins = integration_testutils.MapBroadcastO2I(participants, r2Outs)
	}, func() {
		testutils.DoDkgRound3(participants, r3Ins)
	})
}
