package fuzz

import (
	crand "crypto/rand"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	bbot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot/testutils"
	vsot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	softspoken_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

// TODO: put back ed25519 when bug is fixed
var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), pallas.NewCurve()}

func Fuzz_Test_OTe(f *testing.F) {
	f.Add(uint(0), 3, 2, int64(1))
	f.Add(uint(0), 3, 2, int64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, Xi, L int, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		sessionId := [ot.KappaBytes]byte{}
		prng := rand.New(rand.NewSource(randomSeed))
		_, err := crand.Read(sessionId[:])
		require.NoError(t, err)
		Xi = Xi % 256
		L = L % 3

		cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
		require.NoError(t, err)
		authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
		require.NoError(t, err)
		senderKey, receiverKey := authKeys[0], authKeys[1]

		// BaseOTs
		baseOtSend, baseOtRec, err := bbot_testutils.BBOT(senderKey, receiverKey, curve, sessionId[:], prng, Xi, L)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		err = ot_testutils.ValidateOT(Xi, L, baseOtSend.MessagePairs, baseOtRec.Choices, baseOtRec.ChosenMessages)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Run OTe
		senderMessages, receiverChoices, receiverChosenMessage, err := softspoken_testutils.SoftspokenROTe(
			senderKey, receiverKey, curve, crand.Reader, sessionId[:], nil, baseOtSend, baseOtRec, nil, Xi, L)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		// Check OTe result
		err = ot_testutils.ValidateOT(Xi, L, senderMessages, receiverChoices, receiverChosenMessage)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func Fuzz_Test_COTe(f *testing.F) {
	f.Add(uint(0), 4, 128, int64(1))
	f.Add(uint(0), 4, 256, int64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, L, Xi int, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		sessionId := [ot.KappaBytes]byte{}
		prng := rand.New(rand.NewSource(randomSeed))
		_, err := crand.Read(sessionId[:])
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
		require.NoError(t, err)
		authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
		require.NoError(t, err)
		senderKey, receiverKey := authKeys[0], authKeys[1]

		// BaseOTs
		baseOtSend, baseOtRec, err := vsot_testutils.VSOT(senderKey, receiverKey, curve, sessionId[:], prng, ot.Kappa, 1)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		err = ot_testutils.ValidateOT(Xi, L, baseOtSend.MessagePairs, baseOtRec.Choices, baseOtRec.ChosenMessages)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Run COTe
		x, a, z_A, z_B, err := softspoken_testutils.SoftspokenCOTe(
			senderKey, receiverKey, curve, crand.Reader, sessionId[:], nil, baseOtSend, baseOtRec, nil, L, Xi)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Check COTe result
		err = ot_testutils.ValidateCOT(Xi, L, x, a, z_A, z_B)
		require.NoError(t, err)
	})
}
