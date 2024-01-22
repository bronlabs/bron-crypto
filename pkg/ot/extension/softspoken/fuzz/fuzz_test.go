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
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken/testutils"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}

// func Fuzz_Test_OTe(f *testing.F) {
// 	f.Add(uint(0), 3, 2, int64(1))
// 	f.Add(uint(0), 3, 2, int64(1))
// 	f.Fuzz(func(t *testing.T, curveIndex uint, Xi, LOTe int, randomSeed int64) {
// 		curve := allCurves[int(curveIndex)%len(allCurves)]
// 		uniqueSessionId := [vsot.DigestSize]byte{}
// 		prng := rand.New(rand.NewSource(randomSeed))
// 		_, err := crand.Read(uniqueSessionId[:])
// 		require.NoError(t, err)

// 		// BaseOTs
// 		baseOtSendOutput, baseOtRecOutput, err := testutils.RunBaseOT(t, curve, uniqueSessionId[:], prng)
// 		if err != nil && !errs.IsKnownError(err) {
// 			require.NoError(t, err)
// 		}
// 		if err != nil {
// 			t.Skip()
// 		}
// 		// Set OTe inputs
// 		choices, _, err := testutils.GenerateSoftspokenRandomInputs(curve, LOTe, Xi)
// 		if err != nil && !errs.IsKnownError(err) {
// 			require.NoError(t, err)
// 		}
// 		if err != nil {
// 			t.Skip()
// 		}
// 		// Run OTe
// 		oTeSenderOutput, oTeReceiverOutput, err := testutils.RunSoftspokenOTe(
// 			curve, uniqueSessionId[:], crand.Reader, baseOtSendOutput, baseOtRecOutput, choices, LOTe, Xi)
// 		if err != nil && !errs.IsKnownError(err) {
// 			require.NoError(t, err)
// 		}
// 		// Check OTe result
// 		err = testutils.CheckSoftspokenOTeOutputs(oTeSenderOutput, oTeReceiverOutput, choices, LOTe, Xi)
// 		if err != nil && !errs.IsKnownError(err) {
// 			require.NoError(t, err)
// 		}
// 	})
// }

// TODO: Fix above for below:
// go test fuzz v1
// uint(94)
// int(56)
// int(2)
// int64(1)

func Fuzz_Test_COTe(f *testing.F) {
	f.Add(uint(0), 4, 8, int64(1))
	f.Add(uint(0), 4, 8, int64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, LOTe, Xi int, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		uniqueSessionId := [vsot.DigestSize]byte{}
		prng := rand.New(rand.NewSource(randomSeed))
		_, err := crand.Read(uniqueSessionId[:])
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := testutils.RunBaseOT(t, curve, uniqueSessionId[:], prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		err = testutils.CheckBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Set COTe inputs
		receiverChoices, senderInputs, err := testutils.GenerateSoftspokenRandomInputs(curve, LOTe, Xi)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Run COTe
		senderOutputs, receiverOutputs, err := testutils.RunSoftspokenCOTe(
			curve, uniqueSessionId[:], crand.Reader, baseOtSenderOutput, baseOtReceiverOutput, receiverChoices, senderInputs, LOTe, Xi)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Check COTe result
		err = testutils.CheckSoftspokenCOTeOutputs(receiverChoices, senderInputs, receiverOutputs, senderOutputs, LOTe, Xi)
		require.NoError(t, err)
	})
}
