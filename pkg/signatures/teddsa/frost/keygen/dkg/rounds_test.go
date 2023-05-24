package dkg_test

import (
	"crypto/sha512"
	"fmt"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/test_utils"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func testHappyPath(t *testing.T, curve *curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)

	participants, err := test_utils.MakeDkgParticipants(cohortConfig, identities)
	require.NoError(t, err)

	r1Outs, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1Outs {
		require.NotNil(t, out)
	}

	r2Ins := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1Outs)
	r2OutsB, r2OutsU, err := test_utils.DoDkgRound2(participants, r2Ins)
	require.NoError(t, err)
	for _, out := range r2OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r3InsB, r3InsU := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	signingKeyShares, publicKeyShares, err := test_utils.DoDkgRound3(participants, r3InsB, r3InsU)
	require.NoError(t, err)
	for _, publicKeyShare := range publicKeyShares {
		require.NotNil(t, publicKeyShare)
	}

	// each signing share is different
	for i := 0; i < len(signingKeyShares); i++ {
		for j := i + 1; j < len(signingKeyShares); j++ {
			require.NotZero(t, signingKeyShares[i].Share.Cmp(signingKeyShares[j].Share))
		}
	}

	// each public key is the same
	for i := 0; i < len(signingKeyShares); i++ {
		for j := i + 1; j < len(signingKeyShares); j++ {
			require.True(t, signingKeyShares[i].PublicKey.Equal(signingKeyShares[i].PublicKey))
		}
	}

	shamirDealer, err := sharing.NewShamir(threshold, n, curve)
	require.NoError(t, err)
	require.NotNil(t, shamirDealer)
	shamirShares := make([]*sharing.ShamirShare, len(participants))
	for i := 0; i < len(participants); i++ {
		shamirShares[i] = &sharing.ShamirShare{
			Id:    participants[i].MyShamirId,
			Value: signingKeyShares[i].Share,
		}
	}

	reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
	require.NoError(t, err)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
	require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
}

func testPreviousDkgRoundReuse(t *testing.T, curve *curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	attackerIndex := 0
	require.NoError(t, err)
	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)
	participants, err := test_utils.MakeDkgParticipants(cohortConfig, identities)

	r1Outs, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	r2Ins := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1Outs)
	r2OutsB, r2OutsU, err := test_utils.DoDkgRound2(participants, r2Ins)
	require.NoError(t, err)
	r3InsB, r3InsU := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)

	// smuggle previous value
	r3InsU[attackerIndex][identities[1]].Xij = r2Ins[attackerIndex][identities[1]].Ri
	_, _, err = test_utils.DoDkgRound3(participants, r3InsB, r3InsU)
	require.Error(t, err)
}

func testPreviousDkgExecutionReuse(t *testing.T, curve *curves.Curve, hash func() hash.Hash, tAlpha, nAlpha int, tBeta, nBeta int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	identitiesCount := nAlpha
	if nBeta > nAlpha {
		identitiesCount = nBeta
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, identitiesCount)
	require.NoError(t, err)
	attackerIndex := 0

	// first execution (alpha)
	cohortConfigAlpha, err := test_utils.MakeCohort(cipherSuite, protocol.FROST, identities[:nAlpha], tAlpha, identities[:nAlpha])
	require.NoError(t, err)
	participantsAlpha, err := test_utils.MakeDkgParticipants(cohortConfigAlpha, identities[:nAlpha])
	require.NoError(t, err)
	r1OutsAlpha, err := test_utils.DoDkgRound1(participantsAlpha)
	require.NoError(t, err)
	r2InsAlpha := test_utils.MapDkgRound1OutputsToRound2Inputs(participantsAlpha, r1OutsAlpha)
	r2OutsBAlpha, r2OutsUAlpha, err := test_utils.DoDkgRound2(participantsAlpha, r2InsAlpha)
	require.NoError(t, err)
	r3InsBAlpha, r3InsUAlpha := test_utils.MapDkgRound2OutputsToRound3Inputs(participantsAlpha, r2OutsBAlpha, r2OutsUAlpha)
	_, _, err = test_utils.DoDkgRound3(participantsAlpha, r3InsBAlpha, r3InsUAlpha)
	require.NoError(t, err)

	// second execution (beta)
	cohortConfigBeta, err := test_utils.MakeCohort(cipherSuite, protocol.FROST, identities[:nBeta], tBeta, identities[:nBeta])
	participantsBeta, err := test_utils.MakeDkgParticipants(cohortConfigBeta, identities[:nBeta])
	r1OutsBeta, err := test_utils.DoDkgRound1(participantsBeta)
	require.NoError(t, err)
	r2InsBeta := test_utils.MapDkgRound1OutputsToRound2Inputs(participantsBeta, r1OutsBeta)
	r2OutsBBeta, r2OutsUBeta, err := test_utils.DoDkgRound2(participantsBeta, r2InsBeta)
	require.NoError(t, err)
	r3InsBBeta, r3InsUBeta := test_utils.MapDkgRound2OutputsToRound3Inputs(participantsBeta, r2OutsBBeta, r2OutsUBeta)

	// smuggle previous execution result - replay of the dlog proof
	r3InsBBeta[attackerIndex] = r3InsBAlpha[attackerIndex]
	_, _, err = test_utils.DoDkgRound3(participantsBeta, r3InsBBeta, r3InsUBeta)
	require.Error(t, err)
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 3},
				{t: 3, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestShouldAbortIfAliceReusesValueFromPreviousDkgRound(t *testing.T) {
	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 3},
				{t: 3, n: 5},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testPreviousDkgRoundReuse(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestShouldAbortIfAliceReusesValueFromPreviousDkgExecution(t *testing.T) {
	t.Parallel()

	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				tAlpha int
				nAlpha int
				tBeta  int
				nBeta  int
			}{
				{tAlpha: 3, nAlpha: 5, tBeta: 3, nBeta: 3},
				{tAlpha: 3, nAlpha: 3, tBeta: 4, nBeta: 4},
				{tAlpha: 2, nAlpha: 2, tBeta: 2, nBeta: 2},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Abort test with curve=%s and hash=%s and (t1=%d,n1=%d), (t2=%d,n2=%d)", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.tAlpha, boundedThresholdConfig.nBeta, boundedThresholdConfig.tBeta, boundedThresholdConfig.nBeta), func(t *testing.T) {
					t.Parallel()
					testPreviousDkgExecutionReuse(t, boundedCurve, boundedHash, boundedThresholdConfig.tAlpha, boundedThresholdConfig.nAlpha, boundedThresholdConfig.tBeta, boundedThresholdConfig.nBeta)
				})
			}
		}
	}
}
