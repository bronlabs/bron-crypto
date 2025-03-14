package pedersen_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	randomisedFischlin "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	agreeonrandom_testutils "github.com/bronlabs/bron-crypto/pkg/threshold/agreeonrandom/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/pedersen/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(uniqueSessionId, protocol, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants, nil)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), int(protocol.TotalParties())-1)
	}

	r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
	signingKeyShares, publicKeyShares, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
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
			require.True(t, signingKeyShares[i].PublicKey.Equal(signingKeyShares[j].PublicKey))
		}
	}

	shamirDealer, err := shamir.NewDealer(uint(threshold), uint(n), curve)
	require.NoError(t, err)
	require.NotNil(t, shamirDealer)
	shamirShares := make([]*shamir.Share, len(participants))
	for i := 0; i < len(participants); i++ {
		shamirShares[i] = &shamir.Share{
			Id:    uint(participants[i].SharingId()),
			Value: signingKeyShares[i].Share,
		}
	}

	reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
	require.NoError(t, err)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
	require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
}

func testInvalidSid(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, threshold)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(uniqueSessionId, protocol, identities, nil)
	participants[0].SessionId = []byte("invalid")
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants, nil)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), int(protocol.TotalParties())-1)
	}

	r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
	_, _, err = testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.Error(t, err)
}

func testPreviousDkgRoundReuse(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	attackerIndex := 0
	victimIndex := 1
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, threshold)
	require.NoError(t, err)
	participants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, nil)
	require.NoError(t, err)

	r2OutsB, r2OutsU, err := testutils.DoDkgRound1(participants, nil)
	require.NoError(t, err)

	// smuggle previous value
	msg, exists := r2OutsU[attackerIndex].Get(identities[victimIndex])
	require.True(t, exists)
	msg.Xij = participants[attackerIndex].State.A_i0
	require.NoError(t, err)
	r3InsB, r3InsU := ttu.MapO2I(t, participants, r2OutsB, r2OutsU)
	_, _, err = testutils.DoDkgRound2(participants, r3InsB, r3InsU)
	require.Error(t, err)
	require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
}

func testAliceDlogProofIsUnique(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, threshold)
	require.NoError(t, err)

	// Alpha execution
	alphaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	alphaPrngs[0] = ttu.MakeTestPrng([]byte(
		"A day may come when the courage of men fails. But it is not this day! - Aragorn"))
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	alphaParticipants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, alphaPrngs)
	require.NoError(t, err)
	alphaR1OutsB, alphaR1OutsU, err := testutils.DoDkgRound1(alphaParticipants, nil)
	require.NoError(t, err)
	alphaAliceDlogProof := alphaR1OutsB[0].DlogProof
	require.NoError(t, err)
	alphaR2InsB, alphaR2InsU := ttu.MapO2I(t, alphaParticipants, alphaR1OutsB, alphaR1OutsU)
	_, _, err = testutils.DoDkgRound2(alphaParticipants, alphaR2InsB, alphaR2InsU)
	require.NoError(t, err)

	// Beta execution
	betaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	betaPrngs[0] = ttu.MakeTestPrng([]byte(
		"A day may come when the courage of men fails. But it is not this day! - Aragorn"))
	betaParticipants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, betaPrngs)
	require.NoError(t, err)
	betaR2OutsB, betaR2OutsU, err := testutils.DoDkgRound1(betaParticipants, nil)
	require.NoError(t, err)
	betaAliceDlogProof := betaR2OutsB[0].DlogProof
	require.NoError(t, err)
	betaR3InsB, betaR3InsU := ttu.MapO2I(t, betaParticipants, betaR2OutsB, betaR2OutsU)
	_, _, err = testutils.DoDkgRound2(betaParticipants, betaR3InsB, betaR3InsU)
	require.NoError(t, err)

	require.NotEqual(t, alphaAliceDlogProof, betaAliceDlogProof)
}

func testAliceDlogProofStatementIsSameAsPartialPublicKey(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	prng := ttu.MakeTestPrng([]byte("You have elected the way of ... Pain! - Saruman"))
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	attackerIndex := 0
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, threshold)
	require.NoError(t, err)

	basePoint := cipherSuite.Curve().Generator()
	dlog, err := schnorr.NewSigmaProtocol(basePoint, prng)
	require.NoError(t, err)
	nidlog, err := randomisedFischlin.NewCompiler(dlog, prng)
	require.NoError(t, err)

	t.Run("proving something irrelevant", func(t *testing.T) {
		t.Parallel()
		prover, err := nidlog.NewProver([]byte("sid"), nil)
		require.NoError(t, err)
		randomScalar, err := cipherSuite.Curve().ScalarField().Random(prng)
		require.NoError(t, err)
		statement := basePoint.ScalarMul(randomScalar)
		proof, err := prover.Prove(statement, randomScalar)
		require.NoError(t, err)

		// Run a fresh DKG
		participants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, nil)
		require.NoError(t, err)
		r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants, nil)
		require.NoError(t, err)
		r1OutsB[attackerIndex].DlogProof = proof // smuggle the proof
		r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
		_, _, err = testutils.DoDkgRound2(participants, r2InsB, r2InsU)
		require.Error(t, err)
		require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]),
			"Error %s is not an identifiable abort", err.Error())
	})
	t.Run("pass identity as statement", func(t *testing.T) {
		t.Parallel()
		prover, err := nidlog.NewProver([]byte("sid"), nil)
		require.NoError(t, err)
		randomScalar, err := cipherSuite.Curve().ScalarField().Random(prng)
		require.NoError(t, err)
		proof, err := prover.Prove(cipherSuite.Curve().AdditiveIdentity(), randomScalar)
		require.NoError(t, err)

		// Run a fresh DKG
		participants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, nil)
		require.NoError(t, err)
		r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants, nil)
		require.NoError(t, err)
		r1OutsB[attackerIndex].DlogProof = proof // smuggle the proof
		r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
		_, _, err = testutils.DoDkgRound2(participants, r2InsB, r2InsU)
		require.Error(t, err)
		require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]),
			"Error %s is not an identifiable abort", err.Error())
	})
}

func testAbortOnRogueKeyAttach(t *testing.T, curve curves.Curve, hash func() hash.Hash, n, threshold int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)

	attackerIndex := 0
	victimIndex := 1
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, threshold)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	participants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, nil)
	require.NoError(t, err)
	r2OutsB, r2OutsU, err := testutils.DoDkgRound1(participants, nil)
	require.NoError(t, err)

	// Attacker replaces her C_i[0] with (C_i[0] - Σ Victims' C_i[0])
	for i := range participants {
		if i == attackerIndex {
			continue
		}
		r2OutsB[attackerIndex].Ci[0] = r2OutsB[attackerIndex].Ci[0].Sub(r2OutsB[victimIndex].Ci[0])
	}

	r3InsB, r3InsU := ttu.MapO2I(t, participants, r2OutsB, r2OutsU)
	_, _, err = participants[victimIndex].Round2(r3InsB[victimIndex], r3InsU[victimIndex])
	require.Error(t, err)
	require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
}

func testPreviousDkgExecutionReuse(t *testing.T, curve curves.Curve, hash func() hash.Hash, tAlpha, nAlpha, tBeta, nBeta int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)

	identitiesCount := nAlpha
	if nBeta > nAlpha {
		identitiesCount = nBeta
	}
	identities, err := ttu.MakeTestIdentities(cipherSuite, identitiesCount)
	require.NoError(t, err)
	attackerIndex := 0

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	// first execution (alpha)
	protocolConfigAlpha, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities[:nAlpha], tAlpha)
	require.NoError(t, err)
	participantsAlpha, err := testutils.MakeParticipants(uniqueSessionId, protocolConfigAlpha, identities[:nAlpha], nil)
	require.NoError(t, err)
	r1OutsBAlpha, r1OutsUAlpha, err := testutils.DoDkgRound1(participantsAlpha, nil)
	require.NoError(t, err)
	r2InsBAlpha, r2insUAlpha := ttu.MapO2I(t, participantsAlpha, r1OutsBAlpha, r1OutsUAlpha)
	_, _, err = testutils.DoDkgRound2(participantsAlpha, r2InsBAlpha, r2insUAlpha)
	require.NoError(t, err)

	uniqueSessionId, err = agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	// second execution (beta)
	protocolConfigBeta, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities[:nBeta], tBeta)
	require.NoError(t, err)
	participantsBeta, err := testutils.MakeParticipants(uniqueSessionId, protocolConfigBeta, identities[:nBeta], nil)
	require.NoError(t, err)
	r1OutsBBeta, r1OutsUBeta, err := testutils.DoDkgRound1(participantsBeta, nil)
	require.NoError(t, err)
	r2InsBBeta, r2InsUBeta := ttu.MapO2I(t, participantsBeta, r1OutsBBeta, r1OutsUBeta)

	// smuggle previous execution result - replay of the dlog proof
	r2InsBBeta[attackerIndex] = r2InsBAlpha[attackerIndex]
	_, _, err = testutils.DoDkgRound2(participantsBeta, r2InsBBeta, r2InsUBeta)
	require.Error(t, err)
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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

func TestInvalidSid(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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
					testInvalidSid(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestShouldAbortIfAliceReusesValueFromPreviousDkgRound(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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

func TestAliceDlogProofIsUnique(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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
				t.Run(fmt.Sprintf("Rougue key attack with curve=%s and hash=%s and (t=2,n=2)", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:]), func(t *testing.T) {
					t.Parallel()
					testAbortOnRogueKeyAttach(t, boundedCurve, boundedHash,
						thresholdConfig.n, thresholdConfig.threshold)
				})
			}
		}
	}
}
