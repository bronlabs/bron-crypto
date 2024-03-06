package pedersen_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen/testutils"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	var identities []types.IdentityKey
	var protocolConfig types.ThresholdProtocol
	var uniqueSessionId []byte
	var participants []*pedersen.Participant

	internal.RunMeasurement(500, "pedersen_round1", func(i int) {
		identities, err = ttu.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		protocolConfig, err = ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, 2)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve(), identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, nil)
		require.NoError(t, err)
	}, func() {
		testutils.DoDkgRound1(participants, nil)
	})
}

func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	var identities []types.IdentityKey
	var protocolConfig types.ThresholdProtocol
	var uniqueSessionId []byte
	var participants []*pedersen.Participant
	var r1OutsB []*pedersen.Round1Broadcast
	var r1OutsU []network.RoundMessages[*pedersen.Round1P2P]
	var r2InsB []network.RoundMessages[*pedersen.Round1Broadcast]
	var r2InsU []network.RoundMessages[*pedersen.Round1P2P]

	internal.RunMeasurement(500, "pedersen_round2", func(i int) {
		identities, err = ttu.MakeTestIdentities(cipherSuite, 3)
		require.NoError(t, err)
		protocolConfig, err = ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, 2)
		require.NoError(t, err)
		uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve(), identities, crand.Reader)
		require.NoError(t, err)
		participants, err = testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, nil)
		require.NoError(t, err)
		r1OutsB, r1OutsU, err = testutils.DoDkgRound1(participants, nil)
		require.NoError(t, err)
		r2InsB, r2InsU = ttu.MapO2I(participants, r1OutsB, r1OutsU)
	}, func() {
		testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	})
}
