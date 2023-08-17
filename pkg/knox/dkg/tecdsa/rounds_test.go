package tecdsa_test

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/knox/dkg/tecdsa/test_utils"
)

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) {
	t.Helper()
	if testing.Short() {
		t.Skip()
	}

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.DKLS23, identities, threshold, identities)
	require.NoError(t, err)

	participants, err := test_utils.MakeParticipants(curve, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)

	r2InsB := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB)
	r2OutsB, r2OutsU, err := test_utils.DoDkgRound2(participants, r2InsB)
	require.NoError(t, err)

	r3InsB, r3InsU := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	r3OutsB, r3OutsU, err := test_utils.DoDkgRound3(participants, r3InsB, r3InsU)
	require.NoError(t, err)

	r4InsB, r4InsU := test_utils.MapDkgRound3OutputsToRound4Inputs(participants, r3OutsB, r3OutsU)
	r4OutsB, r4OutsU, err := test_utils.DoDkgRound4(participants, r4InsB, r4InsU)
	require.NoError(t, err)

	r5InsB, r5InsU := test_utils.MapDkgRound4OutputsToRound5Inputs(participants, r4OutsB, r4OutsU)
	r5OutsB, r5OutsU, err := test_utils.DoDkgRound5(participants, r5InsB, r5InsU)
	require.NoError(t, err)

	r6InsB, r6InsU := test_utils.MapDkgRound5OutputsToRound6Inputs(participants, r5OutsB, r5OutsU)
	r6OutsB, r6OutsU, err := test_utils.DoDkgRound6(participants, r6InsB, r6InsU)
	require.NoError(t, err)

	r7InsB, r7InsU := test_utils.MapDkgRound6OutputsToRound7Inputs(participants, r6OutsB, r6OutsU)
	r7OutsU, err := test_utils.DoDkgRound7(participants, r7InsB, r7InsU)
	require.NoError(t, err)

	r8InsU := test_utils.MapDkgRound7OutputsToRound8Inputs(participants, r7OutsU)
	r8OutsU, err := test_utils.DoDkgRound8(participants, r8InsU)
	require.NoError(t, err)

	r9InsU := test_utils.MapDkgRound8OutputsToRound9Inputs(participants, r8OutsU)
	r9OutsU, err := test_utils.DoDkgRound9(participants, r9InsU)
	require.NoError(t, err)

	r10InsU := test_utils.MapDkgRound9OutputsToRound10Inputs(participants, r9OutsU)
	r10OutsU, err := test_utils.DoDkgRound10(participants, r10InsU)
	require.NoError(t, err)

	r11InsU := test_utils.MapDkgRound10OutputsToRound11Inputs(participants, r10OutsU)
	shards, err := test_utils.DoDkgRound11(participants, r11InsU)
	require.NoError(t, err)
	require.Len(t, shards, n)

	// we are combining different protocols and we have tests in their respective packages.
	for _, shard := range shards {
		require.NotNil(t, shard.SigningKeyShare())
		require.NoError(t, shard.SigningKeyShare().Validate())
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{k256.New(), p256.New()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha256.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
