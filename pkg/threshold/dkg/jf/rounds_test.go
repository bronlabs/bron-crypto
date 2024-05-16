package jf_test

import (
	crand "crypto/rand"
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

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

var cn = randomisedFischlin.Name

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int, prng io.Reader) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, prng)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(uniqueSessionId, protocol, identities, cn, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), int(protocol.TotalParties())-1)
	}

	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}
	r3Ins := ttu.MapBroadcastO2I(participants, r2Outs)
	signingKeyShares, publicKeyShares, err := testutils.DoDkgRound3(participants, r3Ins)
	require.NoError(t, err)
	for _, publicKeyShare := range publicKeyShares {
		require.NotNil(t, publicKeyShare)
	}
	require.Len(t, signingKeyShares, n)
	require.Len(t, publicKeyShares, n)

	t.Run("each signing key share is different than all others", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.NotZero(t, signingKeyShares[i].Share.Cmp(signingKeyShares[j].Share))
			}
		}
	})

	t.Run("each public key is the same as all others", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.True(t, signingKeyShares[i].PublicKey.Equal(signingKeyShares[j].PublicKey))
			}
		}
	})

	t.Run("reconstructed private key is the dlog of the public key", func(t *testing.T) {
		t.Parallel()
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
	})
}

func testPreviousDkgRoundReuse(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hash)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	attackerIndex := 0
	victimIndex := 1
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)
	participants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, cn, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)

	r2OutsB, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)
	r3InsB := ttu.MapBroadcastO2I(participants, r2OutsB)

	// smuggle previous value
	msg, exists := r3InsB[attackerIndex].Get(identities[victimIndex])
	require.True(t, exists)
	prevMsg, exists := r2InsB[attackerIndex].Get(identities[victimIndex])
	require.True(t, exists)
	msg.Commitments = prevMsg.BlindedCommitments
	_, _, err = testutils.DoDkgRound3(participants, r3InsB)
	require.True(t, errs.IsIdentifiableAbort(err, nil))
}

func testAliceDlogProofIsUnique(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hash)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	aliceIndex := 0

	// Alpha execution
	alphaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	alphaUniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)
	alphaPrngs[aliceIndex] = rand.New(rand.NewSource(0xcafebabe))
	alphaParticipants, err := testutils.MakeParticipants(alphaUniqueSessionId, protocolConfig, identities, cn, alphaPrngs)
	require.NoError(t, err)
	alphaR1OutsB, alphaR1OutsU, err := testutils.DoDkgRound1(alphaParticipants)
	require.NoError(t, err)
	alphaR2InsB, alphaR2InsU := ttu.MapO2I(alphaParticipants, alphaR1OutsB, alphaR1OutsU)
	alphaR2Outs, err := testutils.DoDkgRound2(alphaParticipants, alphaR2InsB, alphaR2InsU)
	require.NoError(t, err)
	alphaAliceDlogProof := alphaR2Outs[aliceIndex]

	// Beta execution
	betaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	betaUniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)
	betaPrngs[aliceIndex] = rand.New(rand.NewSource(0xcafebabe))
	betaParticipants, err := testutils.MakeParticipants(betaUniqueSessionId, protocolConfig, identities, cn, betaPrngs)
	require.NoError(t, err)
	betaR1OutsB, betaR1OutsU, err := testutils.DoDkgRound1(betaParticipants)
	require.NoError(t, err)
	betaR2InsB, betaR2InsU := ttu.MapO2I(betaParticipants, betaR1OutsB, betaR1OutsU)
	betaR2Outs, err := testutils.DoDkgRound2(betaParticipants, betaR2InsB, betaR2InsU)
	require.NoError(t, err)
	betaAliceDlogProof := betaR2Outs[aliceIndex]
	require.NoError(t, err)

	require.NotEqual(t, alphaAliceDlogProof, betaAliceDlogProof)
}

func testAliceDlogProofStatementIsSameAsPartialPublicKey(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hash)
	require.NoError(t, err)
	prng := rand.New(rand.NewSource(0xcafebabe))
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	attackerIndex := 0
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)
	participants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, cn, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	basePoint := cipherSuite.Curve().Generator()
	dlog, err := schnorr.NewSigmaProtocol(basePoint, prng)
	require.NoError(t, err)
	nidlog, err := compilerUtils.MakeNonInteractive(cn, dlog, prng)
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
		r3Ins := ttu.MapBroadcastO2I(participants, r2Outs)

		for iterator := r3Ins[attackerIndex].Iterator(); iterator.HasNext(); {
			pair := iterator.Next()
			identity := pair.Key
			outMsg, exists := r3Ins[attackerIndex].Get(identity)
			require.True(t, exists)
			outMsg.CommitmentsProof = proof
		}
		_, _, err = testutils.DoDkgRound3(participants, r3Ins)
		require.Error(t, err)
		require.True(t, errs.IsIdentifiableAbort(err, nil))
	})
	t.Run("pass identity as statement", func(t *testing.T) {
		t.Parallel()
		prover, err := nidlog.NewProver([]byte("sid"), nil)
		require.NoError(t, err)
		randomScalar, err := cipherSuite.Curve().ScalarField().Random(prng)
		require.NoError(t, err)
		proof, err := prover.Prove(cipherSuite.Curve().AdditiveIdentity(), randomScalar)
		require.NoError(t, err)
		r3Ins := ttu.MapBroadcastO2I(participants, r2Outs)
		for iterator := r3Ins[attackerIndex].Iterator(); iterator.HasNext(); {
			pair := iterator.Next()
			identity := pair.Key
			outMsg, exists := r3Ins[attackerIndex].Get(identity)
			require.True(t, exists)
			outMsg.CommitmentsProof = proof
		}
		_, _, err = testutils.DoDkgRound3(participants, r3Ins)
		require.Error(t, err)
		require.True(t, errs.IsIdentifiableAbort(err, nil))
	})
}

func testAbortOnRogueKeyAttach(t *testing.T, curve curves.Curve, hash func() hash.Hash) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hash)
	require.NoError(t, err)
	alice := 0
	bob := 1
	identities, err := ttu.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, 2)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, cn, nil)
	require.NoError(t, err)
	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	// Alice replaces her C_i[0] with (C_i[0] - Bob's C_i[0])
	r2Outs[alice].Commitments[0] = r2Outs[alice].Commitments[0].Sub(r2Outs[bob].Commitments[0])
	r3Ins := ttu.MapBroadcastO2I(participants, r2Outs)
	_, _, err = participants[bob].Round3(r3Ins[bob])
	require.True(t, errs.IsIdentifiableAbort(err, nil))
	require.True(t, strings.Contains(err.Error(), "dlog proof"))
}

func testPreviousDkgExecutionReuse(t *testing.T, curve curves.Curve, hash func() hash.Hash, tAlpha, nAlpha, tBeta, nBeta int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hash)
	require.NoError(t, err)

	identitiesCount := nAlpha
	if nBeta > nAlpha {
		identitiesCount = nBeta
	}
	identities, err := ttu.MakeTestIdentities(cipherSuite, identitiesCount)
	require.NoError(t, err)
	attackerIndex := 0

	// first execution (alpha)
	uniqueSessionIdAlpha, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)
	protocolConfigAlpha, err := ttu.MakeThresholdProtocol(curve, identities[:nAlpha], tAlpha)
	require.NoError(t, err)
	participantsAlpha, err := testutils.MakeParticipants(uniqueSessionIdAlpha, protocolConfigAlpha, identities[:nAlpha], cn, nil)
	require.NoError(t, err)
	r1OutsBAlpha, r1OutsUAlpha, err := testutils.DoDkgRound1(participantsAlpha)
	require.NoError(t, err)
	r2InsBAlpha, r2InsUAlpha := ttu.MapO2I(participantsAlpha, r1OutsBAlpha, r1OutsUAlpha)
	_, err = testutils.DoDkgRound2(participantsAlpha, r2InsBAlpha, r2InsUAlpha)
	require.NoError(t, err)

	// second execution (beta)
	protocolConfigBeta, err := ttu.MakeThresholdProtocol(curve, identities[:nBeta], tBeta)
	require.NoError(t, err)
	uniqueSessionIdBeta, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)
	participantsBeta, err := testutils.MakeParticipants(uniqueSessionIdBeta, protocolConfigBeta, identities[:nBeta], cn, nil)
	require.NoError(t, err)
	r1OutsBBeta, r1OutsUBeta, err := testutils.DoDkgRound1(participantsBeta)
	require.NoError(t, err)

	// smuggle previous execution result - replay of the dlog proof
	r1OutsBBeta[attackerIndex] = r1OutsBAlpha[attackerIndex]
	r2InsBBeta, r2InsUBeta := ttu.MapO2I(participantsBeta, r1OutsBBeta, r1OutsUBeta)
	_, err = testutils.DoDkgRound2(participantsBeta, r2InsBBeta, r2InsUBeta)
	require.Error(t, err)
	if tBeta == tAlpha {
		require.True(t, errs.IsIdentifiableAbort(err, nil), "expected identifiable abort, got: %v", err)
	} else {
		require.True(t, errs.IsValidation(err), "expected validation error, got: %v", err)
	}
}

func testInvalidSid(t *testing.T, curve curves.Curve, hash func() hash.Hash, tAlpha, nAlpha, tBeta, nBeta int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hash)
	require.NoError(t, err)
	identitiesCount := nAlpha
	if nBeta > nAlpha {
		identitiesCount = nBeta
	}
	identities, err := ttu.MakeTestIdentities(cipherSuite, identitiesCount)
	require.NoError(t, err)
	attackerIndex := 0

	// first execution (alpha)
	uniqueSessionIdAlpha, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)
	protocolConfigAlpha, err := ttu.MakeThresholdProtocol(curve, identities[:nAlpha], tAlpha)
	require.NoError(t, err)
	participantsAlpha, err := testutils.MakeParticipants(uniqueSessionIdAlpha, protocolConfigAlpha, identities[:nAlpha], cn, nil)
	require.NoError(t, err)
	r1OutsBAlpha, r1OutsUAlpha, err := testutils.DoDkgRound1(participantsAlpha)
	require.NoError(t, err)
	r2InsBAlpha, r2InsUAlpha := ttu.MapO2I(participantsAlpha, r1OutsBAlpha, r1OutsUAlpha)
	_, err = testutils.DoDkgRound2(participantsAlpha, r2InsBAlpha, r2InsUAlpha)
	require.NoError(t, err)

	t.Run("Alice reuses sid from execution alpha", func(t *testing.T) {
		t.Parallel()
		// second execution (beta)
		protocolConfigBeta, err := ttu.MakeThresholdProtocol(curve, identities[:nBeta], tBeta)
		require.NoError(t, err)
		// reused
		uniqueSessionIdBeta, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
		require.NoError(t, err)
		participantsBeta, err := testutils.MakeParticipants(uniqueSessionIdBeta, protocolConfigBeta, identities[:nBeta], cn, nil)
		require.NoError(t, err)
		// reused
		participantsBeta[attackerIndex].SessionId = uniqueSessionIdAlpha
		r1OutsBBeta, r1OutsUBeta, err := testutils.DoDkgRound1(participantsBeta)
		require.NoError(t, err)
		r2InsBBeta, r2InsUBeta := ttu.MapO2I(participantsBeta, r1OutsBBeta, r1OutsUBeta)

		// smuggle previous execution result - replay of the dlog proof
		r2InsBBeta[attackerIndex] = r2InsBAlpha[attackerIndex]
		_, err = testutils.DoDkgRound2(participantsBeta, r2InsBBeta, r2InsUBeta)
		require.Error(t, err)
		if tBeta == tAlpha {
			require.True(t, errs.IsIdentifiableAbort(err, nil), "expected identifiable abort, got: %v", err)
		} else {
			require.True(t, errs.IsValidation(err), "expected validation error, got: %v", err)
		}
	})

	t.Run("Alice uses some garbage as sid", func(t *testing.T) {
		t.Parallel()
		// second execution (beta)
		protocolConfigBeta, err := ttu.MakeThresholdProtocol(curve, identities[:nBeta], tBeta)
		require.NoError(t, err)
		// reused
		uniqueSessionIdBeta, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
		require.NoError(t, err)
		participantsBeta, err := testutils.MakeParticipants(uniqueSessionIdBeta, protocolConfigBeta, identities[:nBeta], cn, nil)
		require.NoError(t, err)
		// some garbage
		participantsBeta[attackerIndex].SessionId = []byte("2 + 2 = 5")
		r1OutsBBeta, r1OutsUBeta, err := testutils.DoDkgRound1(participantsBeta)
		require.NoError(t, err)
		r2InsBBeta, r2InsUBeta := ttu.MapO2I(participantsBeta, r1OutsBBeta, r1OutsUBeta)

		// smuggle previous execution result - replay of the dlog proof
		r2InsBBeta[attackerIndex] = r2InsBAlpha[attackerIndex]
		_, err = testutils.DoDkgRound2(participantsBeta, r2InsBBeta, r2InsUBeta)
		require.Error(t, err)
		if tBeta == tAlpha {
			require.True(t, errs.IsIdentifiableAbort(err, nil), "expected identifiable abort, got: %v", err)
		} else {
			require.True(t, errs.IsValidation(err), "expected validation error, got: %v", err)
		}
	})
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{k256.NewCurve(), edwards25519.NewCurve()} {
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
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, crand.Reader)
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

func TestInvalidSid(t *testing.T) {
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
					testInvalidSid(t, boundedCurve, boundedHash, boundedThresholdConfig.tAlpha, boundedThresholdConfig.nAlpha, boundedThresholdConfig.tBeta, boundedThresholdConfig.nBeta)
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
