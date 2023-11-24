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

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}

func Fuzz_Test_OTe(f *testing.F) {
	f.Add(uint(0), false, 3, 2, int64(1))
	f.Add(uint(0), true, 3, 2, int64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, useForcedReuse bool, inputBatchLen, scalarsPerSlot int, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		uniqueSessionId := [vsot.DigestSize]byte{}
		prng := rand.New(rand.NewSource(randomSeed))
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSendOutput, baseOtRecOutput, err := testutils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		// Set OTe inputs
		choices, _, err := testutils.GenerateSoftspokenRandomInputs(inputBatchLen, scalarsPerSlot, curve, useForcedReuse)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		// Run OTe
		oTeSenderOutput, oTeReceiverOutput, err := testutils.RunSoftspokenOTe(
			curve, uniqueSessionId[:], crand.Reader, baseOtSendOutput, baseOtRecOutput, choices)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		// Check OTe result
		err = testutils.CheckSoftspokenOTeOutputs(oTeSenderOutput, oTeReceiverOutput, choices)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func Fuzz_Test_COTe(f *testing.F) {
	f.Add(uint(0), false, 3, 2, int64(1))
	f.Add(uint(0), true, 3, 2, int64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, useForcedReuse bool, inputBatchLen, scalarsPerSlot int, randomSeed int64) {
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
		baseOtSenderOutput, baseOtReceiverOutput, err := testutils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		err = testutils.CheckSoftspokenBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Set COTe inputs
		choices, inputOpts, err := testutils.GenerateSoftspokenRandomInputs(
			inputBatchLen, scalarsPerSlot, curve, useForcedReuse)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Run COTe
		cOTeSenderOutputs, cOTeMessages, err := testutils.RunSoftspokenCOTe(
			useForcedReuse, curve, uniqueSessionId[:], crand.Reader, baseOtSenderOutput, baseOtReceiverOutput, choices, inputOpts)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Check COTe result
		err = testutils.CheckSoftspokenCOTeOutputs(cOTeSenderOutputs, cOTeMessages, inputOpts, choices)
		require.NoError(t, err)
	})
}
