package gennaro_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var testCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pasta.NewPallasCurve(),
	pasta.NewVestaCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

var testHashes = []func() hash.Hash{
	sha256.New,
	sha3.New256,
	sha512.New,
}

var testAccessStructures = []struct {
	t int
	n int
}{
	{t: 2, n: 2},
	{t: 2, n: 3},
	{t: 3, n: 3},
	{t: 3, n: 5},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range testCurves {
		for _, h := range testHashes {
			for _, thresholdCfg := range testAccessStructures {
				hashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				t.Run(fmt.Sprintf("curve=%s and hash=%s and t=%d and n=%d", curve.Name(), hashName[strings.LastIndex(hashName, "/")+1:], thresholdCfg.t, thresholdCfg.n), func(t *testing.T) {
					t.Parallel()

					testHappyPath(t, curve, h, thresholdCfg.t, thresholdCfg.n)
				})
			}
		}
	}
}

func Test_ShouldAbortIfAliceReusesValueFromPreviousDkgRound(t *testing.T) {
	t.Parallel()

	for _, curve := range testCurves {
		for _, h := range testHashes {
			for _, thresholdCfg := range testAccessStructures {
				hashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				t.Run(fmt.Sprintf("curve=%s and hash=%s and t=%d and n=%d", curve.Name(), hashName[strings.LastIndex(hashName, "/")+1:], thresholdCfg.t, thresholdCfg.n), func(t *testing.T) {
					t.Parallel()

					testPreviousDkgRoundReuse(t, curve, h, thresholdCfg.t, thresholdCfg.n)
				})
			}
		}
	}
}

func Test_ShouldAbortIfAliceReusesValueFromPreviousDkgExecution(t *testing.T) {
	t.Parallel()

	for _, curve := range testCurves {
		for _, h := range testHashes {
			for _, thresholdCfg := range testAccessStructures {
				hashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				t.Run(fmt.Sprintf("curve=%s and hash=%s and t=%d and n=%d", curve.Name(), hashName[strings.LastIndex(hashName, "/")+1:], thresholdCfg.t, thresholdCfg.n), func(t *testing.T) {
					t.Parallel()

					testPreviousDkgExecutionReuse(t, curve, h, thresholdCfg.t, thresholdCfg.n)
				})
			}
		}
	}
}

func Test_ShouldAbortIfAliceTriesRogueKeyAttack(t *testing.T) {
	t.Parallel()

	for _, curve := range testCurves {
		for _, h := range testHashes {
			for _, thresholdCfg := range testAccessStructures {
				hashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				t.Run(fmt.Sprintf("curve=%s and hash=%s and t=%d and n=%d", curve.Name(), hashName[strings.LastIndex(hashName, "/")+1:], thresholdCfg.t, thresholdCfg.n), func(t *testing.T) {
					t.Parallel()

					testAbortOnRogueKeyAttack(t, curve, h, thresholdCfg.t, thresholdCfg.n)
				})
			}
		}
	}
}

func makeTranscripts(tb testing.TB, label string, identities []types.IdentityKey) []transcripts.Transcript {
	tb.Helper()

	allTranscripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		allTranscripts[i] = hagrid.NewTranscript(label, nil)
	}

	return allTranscripts
}

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	tapes := makeTranscripts(t, "test transcript", identities)
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
	require.Len(t, signingKeyShares, n)
	require.Len(t, publicKeyShares, n)

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
		shamirDealer, err := shamir.NewScheme(uint(threshold), uint(n), curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(participants))
		for i := 0; i < len(participants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    participants[i].SharingId(),
				Value: signingKeyShares[i].Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Open(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
	})
}

func testPreviousDkgRoundReuse(tb testing.TB, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	tb.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(tb, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(tb, err)
	attackerIndex := 0
	victimIndex := 1
	tapes := makeTranscripts(tb, "test transcript", identities)
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(tb, err)
	sessionId := []byte("test session id")

	participants, err := testutils.MakeGennaroParticipants(sessionId, protocolConfig, identities, tapes, nil)
	require.NoError(tb, err)
	r1OutsB, err := testutils.DoGennaroRound1(participants)
	require.NoError(tb, err)
	r2InsB := ttu.MapBroadcastO2I(tb, participants, r1OutsB)
	r2OutsB, r2OutsU, err := testutils.DoGennaroRound2(participants, r2InsB)
	require.NoError(tb, err)
	r3InsB, r3InsU := ttu.MapO2I(tb, participants, r2OutsB, r2OutsU)

	// smuggle previous value
	msg, exists := r3InsB[victimIndex].Get(identities[attackerIndex])
	require.True(tb, exists)
	prevMsg, exists := r2InsB[victimIndex].Get(identities[attackerIndex])
	require.True(tb, exists)

	for i := range prevMsg.PedersenVerification {
		msg.FeldmanVerification[i] = prevMsg.PedersenVerification[i]
	}
	_, _, err = testutils.DoGennaroRound3(participants, r3InsB, r3InsU)
	require.True(tb, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
}

func testPreviousDkgExecutionReuse(tb testing.TB, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	tb.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(tb, err)
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(tb, err)
	attackerIndex := 0
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(tb, err)

	// first execution (alpha)
	sessionIdAlpha := []byte("session is test alpha")
	tapesAlpha := makeTranscripts(tb, "alpha transcript", identities)
	participantsAlpha, err := testutils.MakeGennaroParticipants(sessionIdAlpha, protocolConfig, identities, tapesAlpha, nil)
	require.NoError(tb, err)
	r1OutsBAlpha, err := testutils.DoGennaroRound1(participantsAlpha)
	require.NoError(tb, err)
	r2InsBAlpha := ttu.MapBroadcastO2I(tb, participantsAlpha, r1OutsBAlpha)
	_, _, err = testutils.DoGennaroRound2(participantsAlpha, r2InsBAlpha)
	require.NoError(tb, err)

	// second execution (beta)
	sessionIdBeta := []byte("session is test beta")
	tapesBeta := makeTranscripts(tb, "beta transcript", identities)
	participantsBeta, err := testutils.MakeGennaroParticipants(sessionIdBeta, protocolConfig, identities, tapesBeta, nil)
	require.NoError(tb, err)
	r1OutsBBeta, err := testutils.DoGennaroRound1(participantsBeta)
	require.NoError(tb, err)

	// smuggle previous execution result - replay of the dlog proof
	r1OutsBBeta[attackerIndex] = r1OutsBAlpha[attackerIndex]
	r2InsBBeta := ttu.MapBroadcastO2I(tb, participantsBeta, r1OutsBBeta)
	r2OutsBBeta, r2OutsUBeta, err := testutils.DoGennaroRound2(participantsBeta, r2InsBBeta)
	require.NoError(tb, err)

	r3InsBBeta, r3InsUBeta := ttu.MapO2I(tb, participantsBeta, r2OutsBBeta, r2OutsUBeta)
	_, _, err = testutils.DoGennaroRound3(participantsBeta, r3InsBBeta, r3InsUBeta)
	require.True(tb, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
}

func testAbortOnRogueKeyAttack(tb testing.TB, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	tb.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(tb, err)
	attackerIndex := 0
	victimIndex := 1
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(tb, err)
	protocolConfig, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(tb, err)
	sessionId := []byte("the very nice session")
	tapes := makeTranscripts(tb, "rogue key attack", identities)

	participants, err := testutils.MakeGennaroParticipants(sessionId, protocolConfig, identities, tapes, nil)
	require.NoError(tb, err)
	r1OutsB, err := testutils.DoGennaroRound1(participants)
	require.NoError(tb, err)
	r2InsB := ttu.MapBroadcastO2I(tb, participants, r1OutsB)
	r2OutsB, r2OutsU, err := testutils.DoGennaroRound2(participants, r2InsB)
	require.NoError(tb, err)

	// Attacker replaces his C_i[0] with (C_i[0] - Victim's C_i[0])
	for i := range participants {
		if i == attackerIndex {
			continue
		}
		r2OutsB[attackerIndex].FeldmanVerification[0] = r2OutsB[attackerIndex].FeldmanVerification[0].Sub(r2OutsB[victimIndex].FeldmanVerification[0])
	}

	r3InsB, r3InsU := ttu.MapO2I(tb, participants, r2OutsB, r2OutsU)
	_, _, err = participants[victimIndex].Round3(r3InsB[victimIndex], r3InsU[victimIndex])
	require.True(tb, errs.IsIdentifiableAbort(err, identities[attackerIndex]))
}
