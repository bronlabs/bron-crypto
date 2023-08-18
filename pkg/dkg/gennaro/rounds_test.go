package gennaro_test

import (
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"math/rand"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/dkg/gennaro/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
)

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities, threshold, identities)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)

	participants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2Outs, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}
	r3Ins := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
	signingKeyShares, publicKeyShares, err := test_utils.DoDkgRound3(participants, r3Ins)
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
			Id:    participants[i].GetSharingId(),
			Value: signingKeyShares[i].Share,
		}
	}

	reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
	require.NoError(t, err)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
	require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
}

func testPreviousDkgRoundReuse(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	attackerIndex := 0
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities, threshold, identities)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)
	participants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)

	r2OutsB, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)
	r3InsB := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB)

	// smuggle previous value
	r3InsB[attackerIndex][identities[1].Hash()].Commitments = r2InsB[attackerIndex][identities[1].Hash()].BlindedCommitments
	_, _, err = test_utils.DoDkgRound3(participants, r3InsB)
	require.True(t, errs.IsIdentifiableAbort(err, nil))
}

func testAliceDlogProofIsUnique(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities, threshold, identities)
	require.NoError(t, err)
	aliceIndex := 0

	// Alpha execution
	alphaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	alphaUniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)
	alphaPrngs[aliceIndex] = rand.New(rand.NewSource(0xcafebabe))
	alphaParticipants, err := test_utils.MakeParticipants(alphaUniqueSessionId, cohortConfig, identities, alphaPrngs)
	require.NoError(t, err)
	alphaR1OutsB, alphaR1OutsU, err := test_utils.DoDkgRound1(alphaParticipants)
	require.NoError(t, err)
	alphaR2InsB, alphaR2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(alphaParticipants, alphaR1OutsB, alphaR1OutsU)
	alphaR2Outs, err := test_utils.DoDkgRound2(alphaParticipants, alphaR2InsB, alphaR2InsU)
	require.NoError(t, err)
	alphaAliceDlogProof := alphaR2Outs[aliceIndex]

	// Beta execution
	betaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	betaUniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)
	betaPrngs[aliceIndex] = rand.New(rand.NewSource(0xcafebabe))
	betaParticipants, err := test_utils.MakeParticipants(betaUniqueSessionId, cohortConfig, identities, betaPrngs)
	require.NoError(t, err)
	betaR1OutsB, betaR1OutsU, err := test_utils.DoDkgRound1(betaParticipants)
	require.NoError(t, err)
	betaR2InsB, betaR2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(betaParticipants, betaR1OutsB, betaR1OutsU)
	betaR2Outs, err := test_utils.DoDkgRound2(betaParticipants, betaR2InsB, betaR2InsU)
	require.NoError(t, err)
	betaAliceDlogProof := betaR2Outs[aliceIndex]
	require.NoError(t, err)

	require.NotEqual(t, alphaAliceDlogProof, betaAliceDlogProof)
}

func testAliceDlogProofStatementIsSameAsPartialPublicKey(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}
	prng := rand.New(rand.NewSource(0xcafebabe))
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	attackerIndex := 0
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities, threshold, identities)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)
	participants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2Outs, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	t.Run("proving something irrelevant", func(t *testing.T) {
		t.Parallel()
		prover, err := fischlin.NewProver(cipherSuite.Curve.Point().Generator(), uniqueSessionId, nil, prng)
		require.NoError(t, err)
		proof, _, err := prover.Prove(cipherSuite.Curve.Scalar().Random(prng))
		require.NoError(t, err)
		r3Ins := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
		for identity := range r3Ins[attackerIndex] {
			r3Ins[attackerIndex][identity].A_i0Proof = proof
		}
		_, _, err = test_utils.DoDkgRound3(participants, r3Ins)
		require.Error(t, err)
		require.True(t, errs.IsIdentifiableAbort(err, nil))
	})
	t.Run("pass identity as statement", func(t *testing.T) {
		t.Parallel()
		prover, err := fischlin.NewProver(cipherSuite.Curve.Point().Generator(), uniqueSessionId, nil, prng)
		require.NoError(t, err)
		proof, _, err := prover.Prove(cipherSuite.Curve.Scalar().Zero())
		require.NoError(t, err)
		r3Ins := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
		for identity := range r3Ins[attackerIndex] {
			r3Ins[attackerIndex][identity].A_i0Proof = proof
		}
		_, _, err = test_utils.DoDkgRound3(participants, r3Ins)
		require.Error(t, err)
		require.True(t, errs.IsIdentifiableAbort(err, nil))
	})
}

func testAbortOnRogueKeyAttach(t *testing.T, curve curves.Curve, hash func() hash.Hash) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	alice := 0
	bob := 1
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities, 2, identities)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)

	participants, err := test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)
	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2Outs, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	// Alice replaces her C_i[0] with (C_i[0] - Bob's C_i[0])
	r2Outs[alice].Commitments[0] = r2Outs[alice].Commitments[0].Sub(r2Outs[bob].Commitments[0])
	r3Ins := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
	_, _, err = participants[bob].Round3(r3Ins[bob])
	require.True(t, errs.IsIdentifiableAbort(err, nil))
	require.True(t, strings.Contains(err.Error(), "dlog proof"))
}

func testPreviousDkgExecutionReuse(t *testing.T, curve curves.Curve, hash func() hash.Hash, tAlpha, nAlpha, tBeta, nBeta int) {
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

	// first execution (alpha)
	uniqueSessionIdAlpha, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)
	cohortConfigAlpha, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities[:nAlpha], tAlpha, identities[:nAlpha])
	require.NoError(t, err)
	participantsAlpha, err := test_utils.MakeParticipants(uniqueSessionIdAlpha, cohortConfigAlpha, identities[:nAlpha], nil)
	require.NoError(t, err)
	r1OutsBAlpha, r1OutsUAlpha, err := test_utils.DoDkgRound1(participantsAlpha)
	require.NoError(t, err)
	r2InsBAlpha, r2InsUAlpha := test_utils.MapDkgRound1OutputsToRound2Inputs(participantsAlpha, r1OutsBAlpha, r1OutsUAlpha)
	_, err = test_utils.DoDkgRound2(participantsAlpha, r2InsBAlpha, r2InsUAlpha)
	require.NoError(t, err)

	// second execution (beta)
	cohortConfigBeta, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities[:nBeta], tBeta, identities[:nBeta])
	require.NoError(t, err)
	uniqueSessionIdBeta, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)
	participantsBeta, err := test_utils.MakeParticipants(uniqueSessionIdBeta, cohortConfigBeta, identities[:nBeta], nil)
	require.NoError(t, err)
	r1OutsBBeta, r1OutsUBeta, err := test_utils.DoDkgRound1(participantsBeta)
	require.NoError(t, err)
	r2InsBBeta, r2InsUBeta := test_utils.MapDkgRound1OutputsToRound2Inputs(participantsBeta, r1OutsBBeta, r1OutsUBeta)

	// smuggle previous execution result - replay of the dlog proof
	r2InsBBeta[attackerIndex] = r2InsBAlpha[attackerIndex]
	_, err = test_utils.DoDkgRound2(participantsBeta, r2InsBBeta, r2InsUBeta)
	require.Error(t, err)
	require.True(t, errs.IsIdentifiableAbort(err, nil))
}

func testInvalidSid(t *testing.T, curve curves.Curve, hash func() hash.Hash, tAlpha, nAlpha, tBeta, nBeta int) {
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

	// first execution (alpha)
	uniqueSessionIdAlpha, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	require.NoError(t, err)
	cohortConfigAlpha, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities[:nAlpha], tAlpha, identities[:nAlpha])
	require.NoError(t, err)
	participantsAlpha, err := test_utils.MakeParticipants(uniqueSessionIdAlpha, cohortConfigAlpha, identities[:nAlpha], nil)
	require.NoError(t, err)
	r1OutsBAlpha, r1OutsUAlpha, err := test_utils.DoDkgRound1(participantsAlpha)
	require.NoError(t, err)
	r2InsBAlpha, r2InsUAlpha := test_utils.MapDkgRound1OutputsToRound2Inputs(participantsAlpha, r1OutsBAlpha, r1OutsUAlpha)
	_, err = test_utils.DoDkgRound2(participantsAlpha, r2InsBAlpha, r2InsUAlpha)
	require.NoError(t, err)

	t.Run("Alice reuses sid from execution alpha", func(t *testing.T) {
		t.Parallel()
		// second execution (beta)
		cohortConfigBeta, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities[:nBeta], tBeta, identities[:nBeta])
		require.NoError(t, err)
		// reused
		uniqueSessionIdBeta, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
		require.NoError(t, err)
		participantsBeta, err := test_utils.MakeParticipants(uniqueSessionIdBeta, cohortConfigBeta, identities[:nBeta], nil)
		require.NoError(t, err)
		// reused
		participantsBeta[attackerIndex].UniqueSessionId = uniqueSessionIdAlpha
		r1OutsBBeta, r1OutsUBeta, err := test_utils.DoDkgRound1(participantsBeta)
		require.NoError(t, err)
		r2InsBBeta, r2InsUBeta := test_utils.MapDkgRound1OutputsToRound2Inputs(participantsBeta, r1OutsBBeta, r1OutsUBeta)

		// smuggle previous execution result - replay of the dlog proof
		r2InsBBeta[attackerIndex] = r2InsBAlpha[attackerIndex]
		_, err = test_utils.DoDkgRound2(participantsBeta, r2InsBBeta, r2InsUBeta)
		require.Error(t, err)
		require.True(t, errs.IsIdentifiableAbort(err, nil))
	})

	t.Run("Alice uses some garbage as sid", func(t *testing.T) {
		t.Parallel()
		// second execution (beta)
		cohortConfigBeta, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities[:nBeta], tBeta, identities[:nBeta])
		require.NoError(t, err)
		// reused
		uniqueSessionIdBeta, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
		require.NoError(t, err)
		participantsBeta, err := test_utils.MakeParticipants(uniqueSessionIdBeta, cohortConfigBeta, identities[:nBeta], nil)
		require.NoError(t, err)
		// some garbage
		participantsBeta[attackerIndex].UniqueSessionId = []byte("2 + 2 = 5")
		r1OutsBBeta, r1OutsUBeta, err := test_utils.DoDkgRound1(participantsBeta)
		require.NoError(t, err)
		r2InsBBeta, r2InsUBeta := test_utils.MapDkgRound1OutputsToRound2Inputs(participantsBeta, r1OutsBBeta, r1OutsUBeta)

		// smuggle previous execution result - replay of the dlog proof
		r2InsBBeta[attackerIndex] = r2InsBAlpha[attackerIndex]
		_, err = test_utils.DoDkgRound2(participantsBeta, r2InsBBeta, r2InsUBeta)
		require.Error(t, err)
		require.True(t, errs.IsIdentifiableAbort(err, nil))
	})
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestShouldAbortIfAliceReusesValueFromPreviousDkgRound(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testPreviousDkgRoundReuse(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestShouldAbortIfAliceReusesValueFromPreviousDkgExecution(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
				t.Run(fmt.Sprintf("Abort test with curve=%s and hash=%s and (t1=%d,n1=%d), (t2=%d,n2=%d)", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.tAlpha, boundedThresholdConfig.nBeta, boundedThresholdConfig.tBeta, boundedThresholdConfig.nBeta), func(t *testing.T) {
					t.Parallel()
					testPreviousDkgExecutionReuse(t, boundedCurve, boundedHash, boundedThresholdConfig.tAlpha, boundedThresholdConfig.nAlpha, boundedThresholdConfig.tBeta, boundedThresholdConfig.nBeta)
				})
			}
		}
	}
}

func TestInvalidSid(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
				t.Run(fmt.Sprintf("Abort test with curve=%s and hash=%s and (t1=%d,n1=%d), (t2=%d,n2=%d)", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.tAlpha, boundedThresholdConfig.nBeta, boundedThresholdConfig.tBeta, boundedThresholdConfig.nBeta), func(t *testing.T) {
					t.Parallel()
					testInvalidSid(t, boundedCurve, boundedHash, boundedThresholdConfig.tAlpha, boundedThresholdConfig.nAlpha, boundedThresholdConfig.tBeta, boundedThresholdConfig.nBeta)
				})
			}
		}
	}
}

func TestAliceDlogProofIsUnique(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
				t.Run(fmt.Sprintf("Alice DLOG proof is unique with curve=%s and hash=%s and (t=%d,n=%d)", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.threshold, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testAliceDlogProofIsUnique(t, boundedCurve, boundedHash, boundedThresholdConfig.threshold, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestAliceDlogProofStatementIsSameAsPartialPublicKey(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
				t.Run(fmt.Sprintf("Alice DLOG proof is unique with curve=%s and hash=%s and (t=%d,n=%d)", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.threshold, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testAliceDlogProofStatementIsSameAsPartialPublicKey(t, boundedCurve, boundedHash, boundedThresholdConfig.threshold, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestAbortOnRogueKeyAttack(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			boundedCurve := curve
			boundedHash := h
			boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
			t.Run(fmt.Sprintf("Rougue key attack with curve=%s and hash=%s and (t=2,n=2)", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:]), func(t *testing.T) {
				t.Parallel()
				testAbortOnRogueKeyAttach(t, boundedCurve, boundedHash)
			})
		}
	}
}
