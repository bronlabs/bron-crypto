package pedersen_test

import (
	"crypto/sha512"
	"fmt"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"hash"
	"io"
	"math/rand"
	"reflect"
	"runtime"
	"strings"
	"testing"

	agreeonrandom_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/shamir"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func testHappyPath(t *testing.T, curve *curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, n)

	participants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	signingKeyShares, publicKeyShares, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
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

	shamirDealer, err := shamir.NewDealer(threshold, n, curve)
	require.NoError(t, err)
	require.NotNil(t, shamirDealer)
	shamirShares := make([]*shamir.Share, len(participants))
	for i := 0; i < len(participants); i++ {
		shamirShares[i] = &shamir.Share{
			Id:    participants[i].GetShamirId(),
			Value: signingKeyShares[i].Share,
		}
	}

	reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
	require.NoError(t, err)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
	require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
}
func testInvalidSid(t *testing.T, curve *curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, n)

	participants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	participants[0].UniqueSessionId = []byte("invalid")
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	_, _, err = test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.Error(t, err)
}

func testPreviousDkgRoundReuse(t *testing.T, curve *curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, n)
	attackerIndex := 0
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)
	participants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)

	r2OutsB, r2OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	r3InsB, r3InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r2OutsB, r2OutsU)

	// smuggle previous value
	r3InsU[attackerIndex][identities[1]].Xij = curve.Scalar.Hash(uniqueSessionId)
	_, _, err = test_utils.DoDkgRound2(participants, r3InsB, r3InsU)
	require.True(t, errs.IsIdentifiableAbort(err))
}

func testAliceDlogProofIsUnique(t *testing.T, curve *curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)

	// Alpha execution
	alphaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	alphaPrngs[0] = rand.New(rand.NewSource(0xcafebabe))
	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, n)

	alphaParticipants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, alphaPrngs)
	alphaR2OutsB, alphaR2OutsU, err := test_utils.DoDkgRound1(alphaParticipants)
	alphaAliceDlogProof := alphaR2OutsB[0].DlogProof
	require.NoError(t, err)
	alphaR3InsB, alphaR3InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(alphaParticipants, alphaR2OutsB, alphaR2OutsU)
	_, _, err = test_utils.DoDkgRound2(alphaParticipants, alphaR3InsB, alphaR3InsU)
	require.NoError(t, err)

	// Beta execution
	betaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	uniqueSessionId = agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, n)

	betaPrngs[0] = rand.New(rand.NewSource(0xcafebabe))
	betaParticipants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, betaPrngs)
	betaR2OutsB, betaR2OutsU, err := test_utils.DoDkgRound1(betaParticipants)
	betaAliceDlogProof := betaR2OutsB[0].DlogProof
	require.NoError(t, err)
	betaR3InsB, betaR3InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(betaParticipants, betaR2OutsB, betaR2OutsU)
	_, _, err = test_utils.DoDkgRound2(betaParticipants, betaR3InsB, betaR3InsU)
	require.NoError(t, err)

	require.NotEqual(t, alphaAliceDlogProof, betaAliceDlogProof)
}

func testAbortOnRogueKeyAttach(t *testing.T, curve *curves.Curve, hash func() hash.Hash) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	alice := 0
	bob := 1
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, identities, 2, identities)
	require.NoError(t, err)

	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, 2)
	participants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	r2OutsB, r2OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)

	// Alice replaces her C_i[0] with (C_i[0] - Bob's C_i[0])
	r2OutsB[alice].Ci[0] = r2OutsB[alice].Ci[0].Sub(r2OutsB[bob].Ci[0])
	r3InsB, r3InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r2OutsB, r2OutsU)
	_, _, err = test_utils.DoDkgRound2(participants, r3InsB, r3InsU)
	require.True(t, errs.IsFailed(err))
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
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, identitiesCount)
	require.NoError(t, err)
	attackerIndex := 0

	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, 2)
	// first execution (alpha)
	cohortConfigAlpha, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, identities[:nAlpha], tAlpha, identities[:nAlpha])
	require.NoError(t, err)
	participantsAlpha, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfigAlpha, identities[:nAlpha], nil)
	require.NoError(t, err)
	r2OutsBAlpha, r2OutsUAlpha, err := test_utils.DoDkgRound1(participantsAlpha)
	require.NoError(t, err)
	r3InsBAlpha, r3InsUAlpha := test_utils.MapDkgRound1OutputsToRound2Inputs(participantsAlpha, r2OutsBAlpha, r2OutsUAlpha)
	_, _, err = test_utils.DoDkgRound2(participantsAlpha, r3InsBAlpha, r3InsUAlpha)
	require.NoError(t, err)

	uniqueSessionId = agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, 2)
	// second execution (beta)
	cohortConfigBeta, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, identities[:nBeta], tBeta, identities[:nBeta])
	participantsBeta, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfigBeta, identities[:nBeta], nil)
	r2OutsBBeta, r2OutsUBeta, err := test_utils.DoDkgRound1(participantsBeta)
	require.NoError(t, err)
	r3InsBBeta, r3InsUBeta := test_utils.MapDkgRound1OutputsToRound2Inputs(participantsBeta, r2OutsBBeta, r2OutsUBeta)

	// smuggle previous execution result - replay of the dlog proof
	r3InsBBeta[attackerIndex] = r3InsBAlpha[attackerIndex]
	_, _, err = test_utils.DoDkgRound2(participantsBeta, r3InsBBeta, r3InsUBeta)
	require.True(t, errs.IsIdentifiableAbort(err))
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

func TestInvalidSid(t *testing.T) {
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
					testInvalidSid(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
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

func TestAliceDlogProofIsUnique(t *testing.T) {
	t.Parallel()

	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				threshold int
				n         int
			}{
				{threshold: 3, n: 5},
				{threshold: 3, n: 3},
				{threshold: 2, n: 2},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Alice DLOG proof is unique with curve=%s and hash=%s and (t=%d,n=%d)", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.threshold, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testAliceDlogProofIsUnique(t, boundedCurve, boundedHash, boundedThresholdConfig.threshold, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestAbortOnRogueKeyAttack(t *testing.T) {
	t.Parallel()

	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			boundedCurve := curve
			boundedHash := h
			boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
			t.Run(fmt.Sprintf("Rougue key attack with curve=%s and hash=%s and (t=2,n=2)", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:]), func(t *testing.T) {
				t.Parallel()
				testAbortOnRogueKeyAttach(t, boundedCurve, boundedHash)
			})
		}
	}
}
