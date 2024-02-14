package fuzz

import (
	crand "crypto/rand"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	bbot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot/testutils"
	vsot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	softspoken_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}

func Fuzz_Test_OTe(f *testing.F) {
	f.Add(uint(0), 3, 2, int64(1))
	f.Add(uint(0), 3, 2, int64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, Xi, L int, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		uniqueSessionId := [ot.KappaBytes]byte{}
		prng := rand.New(rand.NewSource(randomSeed))
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSend, baseOtRec, err := bbot_testutils.RunBBOT(Xi, L, curve, uniqueSessionId[:], prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		err = ot_testutils.ValidateOT(Xi, L, baseOtSend.Messages, baseOtRec.Choices, baseOtRec.ChosenMessages)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Set OTe inputs
		receiverChoices, _, err := ot_testutils.GenerateOTinputs(Xi, L)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		// Run OTe
		senderMessages, receiverChosenMessage, err := softspoken_testutils.RunSoftspokenOTe(
			Xi, L, curve, uniqueSessionId[:], crand.Reader, baseOtSend, baseOtRec, receiverChoices)
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
		uniqueSessionId := [ot.KappaBytes]byte{}
		prng := rand.New(rand.NewSource(randomSeed))
		_, err := crand.Read(uniqueSessionId[:])
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// BaseOTs
		baseOtSend, baseOtRec, err := vsot_testutils.RunVSOT(ot.Kappa, 1, curve, uniqueSessionId[:], prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		err = ot_testutils.ValidateOT(Xi, L, baseOtSend.Messages, baseOtRec.Choices, baseOtRec.ChosenMessages)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Set COTe inputs
		receiverChoices, senderInputs, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Run COTe
		senderOutputs, receiverOutputs, err := softspoken_testutils.RunSoftspokenCOTe(
			curve, uniqueSessionId[:], crand.Reader, baseOtSend, baseOtRec, receiverChoices, senderInputs, L, Xi)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Check COTe result
		err = ot_testutils.ValidateCOT(Xi, L, receiverChoices, senderInputs, receiverOutputs, senderOutputs)
		require.NoError(t, err)
	})
}
