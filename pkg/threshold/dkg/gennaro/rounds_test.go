package gennaro_test

import (
	"fmt"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/stretchr/testify/require"
	"testing"
)

var testAccessStructures = []struct {
	t uint
	n uint
}{
	{t: 2, n: 2},
	{t: 3, n: 3},
	{t: 3, n: 5},
	{t: 4, n: 8},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, thresholdCfg := range testAccessStructures {
		t.Run(fmt.Sprintf("(%d/%d)", thresholdCfg.t, thresholdCfg.n), func(t *testing.T) {
			t.Parallel()

			t.Run("curve=k256", func(t *testing.T) {
				t.Parallel()
				curve := k256.NewCurve()
				testHappyPath(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=p256", func(t *testing.T) {
				t.Parallel()
				curve := p256.NewCurve()
				testHappyPath(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=edwards25519", func(t *testing.T) {
				t.Parallel()
				curve := edwards25519.NewCurve()
				testHappyPath(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=pallas", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewPallasCurve()
				testHappyPath(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=vesta", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewVestaCurve()
				testHappyPath(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=bls12381g1", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG1Curve()
				testHappyPath(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=bls12381g2", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG2Curve()
				testHappyPath(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
		})
	}
}

func Test_ShouldAbortIfAliceReusesValueFromPreviousDkgRound(t *testing.T) {
	t.Parallel()

	for _, thresholdCfg := range testAccessStructures {
		t.Run(fmt.Sprintf("(%d/%d)", thresholdCfg.t, thresholdCfg.n), func(t *testing.T) {
			t.Parallel()

			t.Run("curve=k256", func(t *testing.T) {
				t.Parallel()
				curve := k256.NewCurve()
				testPreviousDkgRoundReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=p256", func(t *testing.T) {
				t.Parallel()
				curve := p256.NewCurve()
				testPreviousDkgRoundReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=edwards25519", func(t *testing.T) {
				t.Parallel()
				curve := edwards25519.NewCurve()
				testPreviousDkgRoundReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=pallas", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewPallasCurve()
				testPreviousDkgRoundReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=vesta", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewVestaCurve()
				testPreviousDkgRoundReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=bls12381g1", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG1Curve()
				testPreviousDkgRoundReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=bls12381g2", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG2Curve()
				testPreviousDkgRoundReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
		})
	}
}

func Test_ShouldAbortIfAliceReusesValueFromPreviousDkgExecution(t *testing.T) {
	t.Parallel()

	for _, thresholdCfg := range testAccessStructures {
		t.Run(fmt.Sprintf("(%d/%d)", thresholdCfg.t, thresholdCfg.n), func(t *testing.T) {
			t.Parallel()

			t.Run("curve=k256", func(t *testing.T) {
				t.Parallel()
				curve := k256.NewCurve()
				testPreviousDkgExecutionReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=p256", func(t *testing.T) {
				t.Parallel()
				curve := p256.NewCurve()
				testPreviousDkgExecutionReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=edwards25519", func(t *testing.T) {
				t.Parallel()
				curve := edwards25519.NewCurve()
				testPreviousDkgExecutionReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=pallas", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewPallasCurve()
				testPreviousDkgExecutionReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=vesta", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewVestaCurve()
				testPreviousDkgExecutionReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=bls12381g1", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG1Curve()
				testPreviousDkgExecutionReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=bls12381g2", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG2Curve()
				testPreviousDkgExecutionReuse(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
		})
	}
}

func Test_ShouldAbortIfAliceTriesRogueKeyAttack(t *testing.T) {
	t.Parallel()

	for _, thresholdCfg := range testAccessStructures {
		t.Run(fmt.Sprintf("(%d/%d)", thresholdCfg.t, thresholdCfg.n), func(t *testing.T) {
			t.Parallel()

			t.Run("curve=k256", func(t *testing.T) {
				t.Parallel()
				curve := k256.NewCurve()
				testAbortOnRogueKeyAttack(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=p256", func(t *testing.T) {
				t.Parallel()
				curve := p256.NewCurve()
				testAbortOnRogueKeyAttack(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=edwards25519", func(t *testing.T) {
				t.Parallel()
				curve := edwards25519.NewCurve()
				testAbortOnRogueKeyAttack(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=pallas", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewPallasCurve()
				testAbortOnRogueKeyAttack(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=vesta", func(t *testing.T) {
				t.Parallel()
				curve := pasta.NewVestaCurve()
				testAbortOnRogueKeyAttack(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=bls12381g1", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG1Curve()
				testAbortOnRogueKeyAttack(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
			t.Run("curve=bls12381g2", func(t *testing.T) {
				t.Parallel()
				curve := bls12381.NewG2Curve()
				testAbortOnRogueKeyAttack(t, curve, thresholdCfg.t, thresholdCfg.n)
			})
		})
	}
}

func testHappyPath[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C, threshold, n uint) {
	t.Helper()

	identities := ttu.MakeTestIdentities(t, n)
	protocol := ttu.MakeThresholdProtocol(t, curve, threshold, identities...)
	tapes := ttu.MakeTranscripts(t, "test transcript", identities)
	sessionId := []byte("test session id")

	participants, err := testutils.MakeGennaroParticipants(sessionId, protocol, identities, tapes, nil)
	require.NoError(t, err)
	r1OutsB, err := testutils.DoGennaroRound1(participants)
	require.NoError(t, err)

	r2InsB := ttu.MapBroadcastO2I(t, participants, r1OutsB)
	r2OutsB, r2OutsU, err := testutils.DoGennaroRound2(participants, r2InsB)
	require.NoError(t, err)

	r3InsB, r3InsU := ttu.MapO2I(t, participants, r2OutsB, r2OutsU)
	signingKeyShares, publicKeyShares, err := testutils.DoGennaroRound3(participants, r3InsB, r3InsU)
	require.NoError(t, err)
	require.Len(t, signingKeyShares, int(n))
	require.Len(t, publicKeyShares, int(n))

	t.Run("each signing key share is different than all others", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.False(t, signingKeyShares[i].Share.Equal(signingKeyShares[j].Share))
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
		shamirDealer, err := shamir.NewScheme(uint(threshold), uint(n), curve.ScalarField())
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share[S], len(participants))
		for i := 0; i < len(participants); i++ {
			shamirShares[i] = &shamir.Share[S]{
				Id:    participants[i].SharingId(),
				Value: signingKeyShares[i].Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Open(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.Generator().ScalarMul(reconstructedPrivateKey)
		require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
	})
}

func testPreviousDkgRoundReuse[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C, threshold, n uint) {
	t.Helper()

	identities := ttu.MakeTestIdentities(t, n)
	attackerIndex := 0
	victimIndex := 1
	tapes := ttu.MakeTranscripts(t, "test transcript", identities)
	protocolConfig := ttu.MakeThresholdProtocol(t, curve, threshold, identities...)
	sessionId := []byte("test session id")

	participants, err := testutils.MakeGennaroParticipants(sessionId, protocolConfig, identities, tapes, nil)
	require.NoError(t, err)
	r1OutsB, err := testutils.DoGennaroRound1(participants)
	require.NoError(t, err)
	r2InsB := ttu.MapBroadcastO2I(t, participants, r1OutsB)
	r2OutsB, r2OutsU, err := testutils.DoGennaroRound2(participants, r2InsB)
	require.NoError(t, err)
	r3InsB, r3InsU := ttu.MapO2I(t, participants, r2OutsB, r2OutsU)

	// smuggle previous value
	msg, exists := r3InsB[victimIndex].Get(identities[attackerIndex])
	require.True(t, exists)
	prevMsg, exists := r2InsB[victimIndex].Get(identities[attackerIndex])
	require.True(t, exists)

	for i := range prevMsg.PedersenVerification {
		msg.FeldmanVerification[i] = prevMsg.PedersenVerification[i].C
	}
	_, _, err = testutils.DoGennaroRound3(participants, r3InsB, r3InsU)
	require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
}

func testPreviousDkgExecutionReuse[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C, threshold, n uint) {
	t.Helper()

	identities := ttu.MakeTestIdentities(t, n)
	attackerIndex := 0
	protocolConfig := ttu.MakeThresholdProtocol(t, curve, threshold, identities...)

	// first execution (alpha)
	sessionIdAlpha := []byte("session is test alpha")
	tapesAlpha := ttu.MakeTranscripts(t, "alpha transcript", identities)
	participantsAlpha, err := testutils.MakeGennaroParticipants(sessionIdAlpha, protocolConfig, identities, tapesAlpha, nil)
	require.NoError(t, err)
	r1OutsBAlpha, err := testutils.DoGennaroRound1(participantsAlpha)
	require.NoError(t, err)
	r2InsBAlpha := ttu.MapBroadcastO2I(t, participantsAlpha, r1OutsBAlpha)
	_, _, err = testutils.DoGennaroRound2(participantsAlpha, r2InsBAlpha)
	require.NoError(t, err)

	// second execution (beta)
	sessionIdBeta := []byte("session is test beta")
	tapesBeta := ttu.MakeTranscripts(t, "beta transcript", identities)
	participantsBeta, err := testutils.MakeGennaroParticipants(sessionIdBeta, protocolConfig, identities, tapesBeta, nil)
	require.NoError(t, err)
	r1OutsBBeta, err := testutils.DoGennaroRound1(participantsBeta)
	require.NoError(t, err)

	// smuggle previous execution result - replay of the dlog proof
	r1OutsBBeta[attackerIndex] = r1OutsBAlpha[attackerIndex]
	r2InsBBeta := ttu.MapBroadcastO2I(t, participantsBeta, r1OutsBBeta)
	r2OutsBBeta, r2OutsUBeta, err := testutils.DoGennaroRound2(participantsBeta, r2InsBBeta)
	require.NoError(t, err)

	r3InsBBeta, r3InsUBeta := ttu.MapO2I(t, participantsBeta, r2OutsBBeta, r2OutsUBeta)
	_, _, err = testutils.DoGennaroRound3(participantsBeta, r3InsBBeta, r3InsUBeta)
	require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
}

func testAbortOnRogueKeyAttack[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C, threshold, n uint) {
	t.Helper()

	attackerIndex := 0
	victimIndex := 1
	identities := ttu.MakeTestIdentities(t, n)
	protocolConfig := ttu.MakeThresholdProtocol(t, curve, threshold, identities...)
	sessionId := []byte("the very nice session")
	tapes := ttu.MakeTranscripts(t, "rogue key attack", identities)

	participants, err := testutils.MakeGennaroParticipants(sessionId, protocolConfig, identities, tapes, nil)
	require.NoError(t, err)
	r1OutsB, err := testutils.DoGennaroRound1(participants)
	require.NoError(t, err)
	r2InsB := ttu.MapBroadcastO2I(t, participants, r1OutsB)
	r2OutsB, r2OutsU, err := testutils.DoGennaroRound2(participants, r2InsB)
	require.NoError(t, err)

	// Attacker replaces his C_i[0] with (C_i[0] - Victim's C_i[0])
	for i := range participants {
		if i == attackerIndex {
			continue
		}
		r2OutsB[attackerIndex].FeldmanVerification[0] = r2OutsB[attackerIndex].FeldmanVerification[0].Op(r2OutsB[victimIndex].FeldmanVerification[0].OpInv())
	}

	r3InsB, r3InsU := ttu.MapO2I(t, participants, r2OutsB, r2OutsU)
	_, _, err = participants[victimIndex].Round3(r3InsB[victimIndex], r3InsU[victimIndex])
	require.True(t, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
}
