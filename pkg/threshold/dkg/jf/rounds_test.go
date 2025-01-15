package jf_test

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

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dlog/schnorr"
	randomisedFischlin "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	compilerUtils "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	agreeonrandom_testutils "github.com/bronlabs/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
)

var niCompilerName = randomisedFischlin.Name

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

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int, prng io.Reader) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, prng)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(t, uniqueSessionId, protocol, identities, niCompilerName, nil)
	require.NoError(t, err)
	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(t, participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), int(protocol.TotalParties())-1)
	}

	r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(t, participants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}
	r3Ins := ttu.MapBroadcastO2I(t, participants, r2Outs)
	signingKeyShares, publicKeyShares, err := testutils.DoDkgRound3(t, participants, r3Ins)
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

	t.Run("all public key shares are the same", func(t *testing.T) {
		t.Parallel()
		for i, pki := range publicKeyShares {
			for j, pkj := range publicKeyShares {
				if i == j {
					continue
				}
				require.True(t, pki.PublicKey.Equal(pkj.PublicKey))

				for owner, share := range pki.Shares.Iter() {
					otherShare, exists := pkj.Shares.Get(owner)
					require.True(t, exists)
					require.True(t, share.Equal(otherShare))
				}

				for k, vik := range pkj.FeldmanCommitmentVector {
					vjk := pkj.FeldmanCommitmentVector[k]
					require.True(t, vik.Equal(vjk))
				}
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

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	attackerIndex := 0
	victimIndex := 1
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(t, uniqueSessionId, protocolConfig, identities, niCompilerName, nil)
	require.NoError(t, err)
	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(t, participants)
	require.NoError(t, err)
	r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
	r2OutsB, err := testutils.DoDkgRound2(t, participants, r2InsB, r2InsU)
	require.NoError(t, err)
	r3InsB := ttu.MapBroadcastO2I(t, participants, r2OutsB)

	// smuggle previous value
	msg, exists := r3InsB[victimIndex].Get(identities[attackerIndex])
	require.True(t, exists)
	prevMsg, exists := r2InsB[victimIndex].Get(identities[attackerIndex])
	require.True(t, exists)
	msg.Ci = prevMsg.BlindedCommitments
	_, _, err = testutils.DoDkgRound3(t, participants, r3InsB)
	require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
}

func testAliceDlogProofIsUnique(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	aliceIndex := 0

	// Alpha execution
	alphaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	alphaUniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	alphaPrngs[aliceIndex] = ttu.MakeTestPrng([]byte("Blood has been spilled this night - Legolas"))
	alphaParticipants, err := testutils.MakeParticipants(t, alphaUniqueSessionId, protocolConfig, identities, niCompilerName, alphaPrngs)
	require.NoError(t, err)
	alphaR1OutsB, alphaR1OutsU, err := testutils.DoDkgRound1(t, alphaParticipants)
	require.NoError(t, err)
	alphaR2InsB, alphaR2InsU := ttu.MapO2I(t, alphaParticipants, alphaR1OutsB, alphaR1OutsU)
	alphaR2Outs, err := testutils.DoDkgRound2(t, alphaParticipants, alphaR2InsB, alphaR2InsU)
	require.NoError(t, err)
	alphaAliceDlogProof := alphaR2Outs[aliceIndex]

	// Beta execution
	betaPrngs := make([]io.Reader, n)
	// force to use the same data for Alice
	betaUniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	betaPrngs[aliceIndex] = ttu.MakeTestPrng([]byte("Certainty of death? What are we waitin' for? - Gimli"))
	betaParticipants, err := testutils.MakeParticipants(t, betaUniqueSessionId, protocolConfig, identities, niCompilerName, betaPrngs)
	require.NoError(t, err)
	betaR1OutsB, betaR1OutsU, err := testutils.DoDkgRound1(t, betaParticipants)
	require.NoError(t, err)
	betaR2InsB, betaR2InsU := ttu.MapO2I(t, betaParticipants, betaR1OutsB, betaR1OutsU)
	betaR2Outs, err := testutils.DoDkgRound2(t, betaParticipants, betaR2InsB, betaR2InsU)
	require.NoError(t, err)
	betaAliceDlogProof := betaR2Outs[aliceIndex]

	require.NotEqual(t, alphaAliceDlogProof, betaAliceDlogProof)
}

func testAliceDlogProofStatementIsSameAsPartialPublicKey(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	prng := ttu.MakeTestPrng([]byte("You Have No Power Here - Theoden"))
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	attackerIndex := 0
	require.NoError(t, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(t, uniqueSessionId, protocolConfig, identities, niCompilerName, nil)
	require.NoError(t, err)
	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(t, participants)
	require.NoError(t, err)
	r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(t, participants, r2InsB, r2InsU)
	require.NoError(t, err)

	basePoint := cipherSuite.Curve().Generator()
	dlog, err := schnorr.NewSigmaProtocol(basePoint, prng)
	require.NoError(t, err)
	nidlog, err := compilerUtils.MakeNonInteractive(niCompilerName, dlog, prng)
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
		r3Ins := ttu.MapBroadcastO2I(t, participants, r2Outs)

		// smuggle the proof
		for i := range participants {
			if i == attackerIndex {
				continue
			}
			outMsg, exists := r3Ins[i].Get(identities[attackerIndex])
			require.True(t, exists)
			outMsg.CommitmentsProof = proof
		}
		// Reuse the same participants as before, make them expect Round 3
		for i := range participants {
			participants[i].Round = 3
		}
		_, _, err = testutils.DoDkgRound3(t, participants, r3Ins)
		require.Error(t, err)
		require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
	})
	t.Run("pass identity as statement", func(t *testing.T) {
		t.Parallel()
		prover, err := nidlog.NewProver([]byte("sid"), nil)
		require.NoError(t, err)
		randomScalar, err := cipherSuite.Curve().ScalarField().Random(prng)
		require.NoError(t, err)
		proof, err := prover.Prove(cipherSuite.Curve().AdditiveIdentity(), randomScalar)
		require.NoError(t, err)
		r3Ins := ttu.MapBroadcastO2I(t, participants, r2Outs)

		// smuggle the proof
		for i := range participants {
			if i == attackerIndex {
				continue
			}
			outMsg, exists := r3Ins[i].Get(identities[attackerIndex])
			require.True(t, exists)
			outMsg.CommitmentsProof = proof
		}

		// Reuse the same participants as before, make them expect Round 3
		for i := range participants {
			participants[i].Round = 3
		}
		//_, _, err = testutils.DoDkgRound3(participants, r3Ins)
		//require.Error(t, err)
		//require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
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
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(t, uniqueSessionId, protocolConfig, identities, niCompilerName, nil)
	require.NoError(t, err)
	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(t, participants)
	require.NoError(t, err)
	r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
	r2OutsB, err := testutils.DoDkgRound2(t, participants, r2InsB, r2InsU)
	require.NoError(t, err)

	// Attacker replaces his C_i[0] with (C_i[0] - Victim's C_i[0])
	for i := range participants {
		if i == attackerIndex {
			continue
		}
		r2OutsB[attackerIndex].Ci[0] = r2OutsB[attackerIndex].Ci[0].Sub(r2OutsB[victimIndex].Ci[0])
	}

	_ = ttu.MapBroadcastO2I(t, participants, r2OutsB)
	r3Ins := ttu.MapBroadcastO2I(t, participants, r2OutsB)
	_, _, err = participants[victimIndex].Round3(r3Ins[victimIndex])
	require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
	require.ErrorContains(t, err, "dlog proof")
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

	// first execution (alpha)
	uniqueSessionIdAlpha, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	protocolConfigAlpha, err := ttu.MakeThresholdProtocol(curve, identities[:nAlpha], tAlpha)
	require.NoError(t, err)
	participantsAlpha, err := testutils.MakeParticipants(t, uniqueSessionIdAlpha, protocolConfigAlpha, identities[:nAlpha], niCompilerName, nil)
	require.NoError(t, err)
	r1OutsBAlpha, r1OutsUAlpha, err := testutils.DoDkgRound1(t, participantsAlpha)
	require.NoError(t, err)
	r2InsBAlpha, r2InsUAlpha := ttu.MapO2I(t, participantsAlpha, r1OutsBAlpha, r1OutsUAlpha)
	_, err = testutils.DoDkgRound2(t, participantsAlpha, r2InsBAlpha, r2InsUAlpha)
	require.NoError(t, err)

	// second execution (beta)
	protocolConfigBeta, err := ttu.MakeThresholdProtocol(curve, identities[:nBeta], tBeta)
	require.NoError(t, err)
	uniqueSessionIdBeta, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	participantsBeta, err := testutils.MakeParticipants(t, uniqueSessionIdBeta, protocolConfigBeta, identities[:nBeta], niCompilerName, nil)
	require.NoError(t, err)
	r1OutsBBeta, r1OutsUBeta, err := testutils.DoDkgRound1(t, participantsBeta)
	require.NoError(t, err)

	// smuggle previous execution result - replay of the dlog proof
	r1OutsBBeta[attackerIndex] = r1OutsBAlpha[attackerIndex]
	r2InsBBeta, r2InsUBeta := ttu.MapO2I(t, participantsBeta, r1OutsBBeta, r1OutsUBeta)
	_, err = testutils.DoDkgRound2(t, participantsBeta, r2InsBBeta, r2InsUBeta)
	require.Error(t, err)
	if tBeta == tAlpha {
		require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
	} else {
		require.True(t, errs.IsValidation(err), "expected validation error, got: %v", err)
	}
}

func testInvalidSid(t *testing.T, curve curves.Curve, hash func() hash.Hash, tAlpha, nAlpha, tBeta, nBeta int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identitiesCount := nAlpha
	if nBeta > nAlpha {
		identitiesCount = nBeta
	}
	identities, err := ttu.MakeTestIdentities(cipherSuite, identitiesCount)
	require.NoError(t, err)
	faultyIndex := 0

	// first execution (alpha)
	uniqueSessionIdAlpha, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)
	protocolConfigAlpha, err := ttu.MakeThresholdProtocol(curve, identities[:nAlpha], tAlpha)
	require.NoError(t, err)

	participantsAlpha, err := testutils.MakeParticipants(t, uniqueSessionIdAlpha, protocolConfigAlpha, identities[:nAlpha], niCompilerName, nil)
	require.NoError(t, err)
	r1OutsBAlpha, r1OutsUAlpha, err := testutils.DoDkgRound1(t, participantsAlpha)
	require.NoError(t, err)
	r2InsBAlpha, r2InsUAlpha := ttu.MapO2I(t, participantsAlpha, r1OutsBAlpha, r1OutsUAlpha)
	_, err = testutils.DoDkgRound2(t, participantsAlpha, r2InsBAlpha, r2InsUAlpha)
	require.NoError(t, err)

	t.Run("Alice reuses sid from execution alpha", func(t *testing.T) {
		t.Parallel()
		// second execution (beta)
		protocolConfigBeta, err := ttu.MakeThresholdProtocol(curve, identities[:nBeta], tBeta)
		require.NoError(t, err)
		// reused
		uniqueSessionIdBeta, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
		require.NoError(t, err)
		participantsBeta, err := testutils.MakeParticipants(t, uniqueSessionIdBeta, protocolConfigBeta, identities[:nBeta], niCompilerName, nil)
		require.NoError(t, err)
		// reused
		participantsBeta[faultyIndex].SessionId = uniqueSessionIdAlpha
		r1OutsBBeta, r1OutsUBeta, err := testutils.DoDkgRound1(t, participantsBeta)
		require.NoError(t, err)
		r2InsBBeta, r2InsUBeta := ttu.MapO2I(t, participantsBeta, r1OutsBBeta, r1OutsUBeta)

		// smuggle previous execution result - replay of the dlog proof
		r2InsBBeta[faultyIndex] = r2InsBAlpha[faultyIndex]
		_, err = testutils.DoDkgRound2(t, participantsBeta, r2InsBBeta, r2InsUBeta)
		require.Error(t, err)
		if tBeta == tAlpha {
			require.True(t, errs.IsFailed(err))
			require.ErrorContains(t, err, fmt.Sprintf("%s could not run JF round 2", identities[faultyIndex].String()))
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
		uniqueSessionIdBeta, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
		require.NoError(t, err)

		participantsBeta, err := testutils.MakeParticipants(t, uniqueSessionIdBeta, protocolConfigBeta, identities[:nBeta], niCompilerName, nil)
		require.NoError(t, err)

		// some garbage
		participantsBeta[faultyIndex].SessionId = []byte("2 + 2 = 5")
		r1OutsBBeta, r1OutsUBeta, err := testutils.DoDkgRound1(t, participantsBeta)
		require.NoError(t, err)
		r2InsBBeta, r2InsUBeta := ttu.MapO2I(t, participantsBeta, r1OutsBBeta, r1OutsUBeta)

		//smuggle previous execution result - replay of the dlog proof
		r2InsBBeta[faultyIndex] = r2InsBAlpha[faultyIndex]
		_, err = testutils.DoDkgRound2(t, participantsBeta, r2InsBBeta, r2InsUBeta)
		require.Error(t, err)
		if tBeta == tAlpha {
			require.True(t, errs.IsFailed(err))
			require.ErrorContains(t, err, fmt.Sprintf("%s could not run JF round 2", identities[faultyIndex].String()))
		} else {
			require.True(t, errs.IsValidation(err), "expected validation error, got: %v", err)
		}
	})
}
