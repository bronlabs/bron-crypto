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
	f.Add(uint(0), false, 3, int64(1))
	f.Add(uint(0), true, 3, int64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, useForcedReuse bool, inputBatchLen int, randomSeed int64) {
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
		choices, _, err := testutils.GenerateSoftspokenRandomInputs(inputBatchLen, curve, useForcedReuse)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		// Run OTe
		oTeSenderOutput, oTeReceiverOutput, err := testutils.RunSoftspokenOTe(
			curve, uniqueSessionId[:], baseOtSendOutput, baseOtRecOutput, choices)
		require.NoError(t, err)
		// Check OTe result
		err = testutils.CheckSoftspokenOTeOutputs(oTeSenderOutput, oTeReceiverOutput, choices)
		require.NoError(t, err)
	})
}

func Fuzz_Test_COTe(f *testing.F) {
	f.Add(uint(0), false, 3, int64(1))
	f.Add(uint(0), true, 3, int64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, useForcedReuse bool, inputBatchLen int, randomSeed int64) {
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
			inputBatchLen, curve, useForcedReuse)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Run COTe
		cOTeSenderOutputs, cOTeReceiverOutputs, err := testutils.RunSoftspokenCOTe(
			useForcedReuse, curve, uniqueSessionId[:], baseOtSenderOutput, baseOtReceiverOutput, choices, inputOpts)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		// Check COTe result
		err = testutils.CheckSoftspokenCOTeOutputs(cOTeSenderOutputs, cOTeReceiverOutputs, inputOpts, choices)
		require.NoError(t, err)
	})
}
