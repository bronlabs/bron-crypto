package test_utils

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/ot/extension/softspoken"
)

// ------------------------------ BASE OTs ---------------------------------- //
// RunSoftspokenBaseOT is a utility function encapsulating the entire process of
// running a base OT, so that other tests can use it / bootstrap themselves.
// As a black box, this function uses randomised inputs, and does:
//
//	.             ┌---> R: k^i_{Δ_i}, Δ_i
//	BaseOT_{κ}()--┤
//	.             └---> S: k^i_0, k^i_1
func RunSoftspokenBaseOT(t *testing.T, curve curves.Curve, sid []byte) (*vsot.SenderOutput, *vsot.ReceiverOutput, error) {
	t.Helper() // TODO: remove *testing.T from most Run test_util functions. Use errors instead.
	senderOutput, receiverOutput, err := test_utils.RunVSOT(t, curve, softspoken.Kappa, sid)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "Base OT run failed")
	}
	return senderOutput, receiverOutput, nil
}

// CheckSoftspokenBaseOTOutputs checks the results of a base OT run, testing
// that k^i_{Δ_i} = k^i_1 • Δ_i + k^i_0 • (1-Δ_i).
func CheckSoftspokenBaseOTOutputs(baseOtSenderOutput *vsot.SenderOutput, baseOtReceiverOutput *vsot.ReceiverOutput) error {
	// Check length matching
	Kappa := len(baseOtSenderOutput.OneTimePadEncryptionKeys)
	if len(baseOtReceiverOutput.RandomChoiceBits) != Kappa || Kappa != softspoken.Kappa {
		return errs.NewInvalidLength("baseOT output length mismatch")
	}
	// Check baseOT results
	for i := 0; i < Kappa; i++ {
		if !bytes.Equal(baseOtReceiverOutput.OneTimePadDecryptionKey[i][:],
			baseOtSenderOutput.OneTimePadEncryptionKeys[i][baseOtReceiverOutput.RandomChoiceBits[i]][:]) {
			return errs.NewVerificationFailed("baseOT output mismatch for index %d", i)
		}
	}
	return nil
}

// ----------------------------- OT extension ------------------------------- //
// RunSoftspokenOTe is a utility function encapsulating the entire process of
// running a random OT extension without derandomization.
// As a black box, this function does:
//
//		R: x ---┐                        ┌---> R: (v_x)
//		        ├--- COTe_{κ, L, M}(x)---┤
//		S:   ---┘                        └---> S: (v_0, v_1)
//	 s.t. v_x = v_1 • (x) + v_0 • (1-x)
func RunSoftspokenOTe(
	curve curves.Curve,
	sid []byte,
	baseOtSenderOutput *vsot.SenderOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *vsot.ReceiverOutput, // baseOT seeds for OTe sender
	choices softspoken.OTeInputChoices, // receiver's input, the Choice bits x
) (oTeSenderOutputs *softspoken.OTeSenderOutput, oTeReceiverOutputs softspoken.OTeReceiverOutput, err error) {
	// Setup OTe
	useForcedReuse := false
	sender, err := softspoken.NewCOtSender(baseOtReceiverOutput, sid, nil, curve, useForcedReuse)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken sender")
	}
	receiver, err := softspoken.NewCOtReceiver(baseOtSenderOutput, sid, nil, curve, useForcedReuse)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken receiver")
	}

	// Run OTe
	oTeReceiverOutput, round1Output, err := receiver.Round1ExtendAndProveConsistency(choices)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 1")
	}
	oTeSenderOutput, _, _, err := sender.Round2ExtendAndCheckConsistency(round1Output, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken sender round 2")
	}
	return oTeSenderOutput, oTeReceiverOutput, nil
}

// CheckSoftspokenOTeOutputs checks the results of a random OT extension run,
// testing that v_x = v_1 • x + v_0 • (1-x).
func CheckSoftspokenOTeOutputs(
	oTeSenderOutput *softspoken.OTeSenderOutput, // (v_0, v_1)
	oTeReceiverOutput softspoken.OTeReceiverOutput, // (v_x)
	choices softspoken.OTeInputChoices, // receiver's input, the Choice bits x
) error {
	L := len(oTeSenderOutput[0])
	// Check length matching
	if len(oTeReceiverOutput) != L {
		return errs.NewInvalidLength("OTe output length mismatch")
	}
	// Check OTe results
	for l := 0; l < L; l++ {
		for i := 0; i < softspoken.Xi; i++ {
			// Check that v_x = v_1 • x + v_0 • (1-x)
			xBit := bitstring.SelectBit(choices[l][:], i)
			for j := 0; j < softspoken.ROTeWidth; j++ {
				if !bytes.Equal(oTeSenderOutput[xBit][l][i][j][:], oTeReceiverOutput[l][i][j][:]) {
					return errs.NewVerificationFailed("OTe output mismatch for index %d", i)
				}
			}
		}
	}
	return nil
}

// ------------------------- Correlated OT extension ------------------------ //
// RunSoftspokenCOTe is a utility function encapsulating the entire process of
// running a SoftspokenOT extension and derandomizing its result.
// As a black box, this function does:
//
//		R: x ---┐                           ┌---> R: z_B
//		        ├--- COTe_{κ, L, M}(x, α)---┤
//		S: α ---┘                           └---> S: z_A
//	 s.t. z_A + z_B = x • α
//
// If useForcedReuse: use a single OTe batch for all the inputOpt batches.
// NOTE: it should only be used by setting L=1 in "participants.go".
func RunSoftspokenCOTe(
	useForcedReuse bool,
	curve curves.Curve,
	sid []byte,
	baseOtSenderOutput *vsot.SenderOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *vsot.ReceiverOutput, // baseOT seeds for OTe sender
	choices softspoken.OTeInputChoices, // receiver's input, the Choice bits x
	inputOpts softspoken.COTeInputOpt, // sender's input, the InputOpt batches of α
) (cOTeSenderOutput softspoken.COTeSenderOutput, cOTeReceiverOutput softspoken.COTeReceiverOutput, err error) {
	// Setup COTe
	sender, err := softspoken.NewCOtSender(baseOtReceiverOutput, sid, nil, curve, useForcedReuse)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken sender")
	}
	receiver, err := softspoken.NewCOtReceiver(baseOtSenderOutput, sid, nil, curve, useForcedReuse)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken receiver")
	}

	// Run COTe
	oTeReceiverOutput, round1Output, err := receiver.Round1ExtendAndProveConsistency(choices)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 1")
	}
	_, cOTeSenderOutput, round2Output, err := sender.Round2ExtendAndCheckConsistency(round1Output, inputOpts)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken sender round 2")
	}
	cOTeReceiverOutput, err = receiver.Round3Derandomize(round2Output, oTeReceiverOutput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 3")
	}
	return cOTeSenderOutput, cOTeReceiverOutput, nil
}

// GenerateSoftspokenRandomInputs generates random inputs for the SoftspokenOT
// Correlated OT extension.
func GenerateSoftspokenRandomInputs(inputBatchLen int, curve curves.Curve, useForcedReuse bool) (
	choices softspoken.OTeInputChoices, // receiver's input, the Choice bits x
	inputOpts softspoken.COTeInputOpt, // sender's input, the InputOpt α
	err error,
) {
	choicesBatchLen := inputBatchLen // L = inputBatchLen in the general case
	if useForcedReuse {              // L = 1 in the forced reuse case
		choicesBatchLen = 1
	}
	choices = make(softspoken.OTeInputChoices, choicesBatchLen)
	for l := 0; l < choicesBatchLen; l++ {
		if _, err := rand.Read(choices[l][:]); err != nil {
			return nil, nil, errs.WrapFailed(err, "could not generate random choice bits")
		}
	}
	if curve == nil { // Just need the input choices
		return choices, nil, nil
	}
	inputOpts = make(softspoken.COTeInputOpt, inputBatchLen)
	for l := 0; l < inputBatchLen; l++ {
		for i := 0; i < softspoken.Xi; i++ {
			for k := 0; k < softspoken.ROTeWidth; k++ {
				inputOpts[l][i][k] = curve.Scalar().Random(rand.Reader)
			}
		}
	}
	return choices, inputOpts, nil
}

// CheckSoftspokenCOTeOutputs checks the results of a Correlated OT extension run,
// testing that z_A + z_B = x • α.
func CheckSoftspokenCOTeOutputs(
	cOTeSenderOutputs softspoken.COTeSenderOutput,
	cOTeReceiverOutputs softspoken.COTeReceiverOutput,
	inputOpts softspoken.COTeInputOpt,
	choices softspoken.OTeInputChoices,
) error {
	L := len(inputOpts)
	useForcedReuse := (len(choices) == 1) && (L > 1)
	// Check length matching
	// require.Equal(t, len(cOTeSenderOutputs), L)
	// require.Equal(t, len(cOTeReceiverOutputs), L)
	if len(cOTeSenderOutputs) != L || len(cOTeReceiverOutputs) != L {
		return errs.NewInvalidLength("COTe input/output length mismatch")
	}
	// Check correlation in COTe results
	var idxOTe int
	for l := 0; l < L; l++ {
		for i := 0; i < softspoken.Xi; i++ {
			// if forced reuse, use always the first OTe batch (idxOTe = 0)
			if useForcedReuse {
				idxOTe = 0
			} else {
				idxOTe = l
			}
			x := bitstring.SelectBit(choices[idxOTe][:], i)
			for k := 0; k < softspoken.ROTeWidth; k++ {
				// Check each correlation z_A = x • α - z_B
				z_A := cOTeSenderOutputs[l][i][k]
				z_B := cOTeReceiverOutputs[l][i][k]
				alpha := inputOpts[l][i][k]
				if x != 0 {
					if z_A.Cmp(alpha.Sub(z_B)) != 0 {
						return errs.NewVerificationFailed("COTe output mismatch for index %d", i)
					}
				} else {
					if z_A.Cmp(z_B.Neg()) != 0 {
						return errs.NewVerificationFailed("COTe output mismatch for index %d", i)
					}
				}
			}
		}
	}
	return nil
}
