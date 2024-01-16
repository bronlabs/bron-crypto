package testutils

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
)

// ------------------------------ BASE OTs ---------------------------------- //
// RunSoftspokenBaseOT is a utility function encapsulating the entire process of
// running a base OT, so that other tests can use it / bootstrap themselves.
// As a black box, this function uses randomised inputs, and does:
//
//	.             ┌---> R: k^i_{Δ_i}, Δ_i
//	BaseOT_{κ}()--┤
//	.             └---> S: k^i_0, k^i_1
func RunSoftspokenBaseOT(t *testing.T, curve curves.Curve, sid []byte, prng io.Reader) (*vsot.SenderOutput, *vsot.ReceiverOutput, error) {
	t.Helper() // TODO: remove *testing.T from most Run test_util functions. Use errors instead.
	senderOutput, receiverOutput, err := testutils.RunVSOT(t, curve, softspoken.Kappa, sid, prng)
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
	rand io.Reader,
	baseOtSenderOutput *vsot.SenderOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *vsot.ReceiverOutput, // baseOT seeds for OTe sender
	choices softspoken.OTeInputChoices, // receiver's input, the Choice bits x
) (oTeSenderOutputs *[2]softspoken.OTeMessage, oTeReceiverOutputs softspoken.OTeMessage, err error) {
	// Setup OTe
	useForcedReuse := false
	sender, err := softspoken.NewCOtSender(baseOtReceiverOutput, sid, nil, curve, rand, useForcedReuse, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken sender")
	}
	receiver, err := softspoken.NewCOtReceiver(baseOtSenderOutput, sid, nil, curve, rand, useForcedReuse, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken receiver")
	}

	// Run OTe
	oTeReceiverOutput, round1Output, err := receiver.Round1(choices)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 1")
	}
	oTeSenderOutput, _, _, err := sender.Round2(round1Output, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken sender round 2")
	}
	return oTeSenderOutput, oTeReceiverOutput, nil
}

// CheckSoftspokenOTeOutputs checks the results of a random OT extension run,
// testing that v_x = v_1 • x + v_0 • (1-x).
func CheckSoftspokenOTeOutputs(
	oTeSenderOutput *[2]softspoken.OTeMessage, // (v_0, v_1)
	oTeReceiverOutput softspoken.OTeMessage, // (v_x)
	choices softspoken.OTeInputChoices, // receiver's input, the Choice bits x
) error {
	if oTeSenderOutput == nil || oTeReceiverOutput == nil {
		return errs.NewInvalidLength("OTe input/output is nil")
	}
	L := len(oTeSenderOutput[0])
	// Check length matching
	if len(oTeReceiverOutput) != L {
		return errs.NewInvalidLength("OTe output length mismatch (is %d, should be %d)", len(oTeReceiverOutput), L)
	}
	// Check OTe results
	for l := 0; l < L; l++ {
		for i := 0; i < softspoken.Xi; i++ {
			// Check that v_x = v_1 • x + v_0 • (1-x)
			xBit, err := bitstring.SelectBit(choices[l][:], i)
			if err != nil {
				return errs.WrapFailed(err, "cannot select bit")
			}
			if !bytes.Equal(oTeSenderOutput[xBit][l][i][:], oTeReceiverOutput[l][i][:]) {
				return errs.NewVerificationFailed("OTe output mismatch for index %d", i)
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
	rand io.Reader,
	baseOtSenderOutput *vsot.SenderOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *vsot.ReceiverOutput, // baseOT seeds for OTe sender
	choices softspoken.OTeInputChoices, // receiver's input, the Choice bits x
	inputOpts softspoken.COTeMessage, // sender's input, the InputOpt batches of α
) (cOTeSenderOutput, cOTeMessage softspoken.COTeMessage, err error) {
	// Setup COTe
	sender, err := softspoken.NewCOtSender(baseOtReceiverOutput, sid, nil, curve, rand, useForcedReuse, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken sender")
	}
	receiver, err := softspoken.NewCOtReceiver(baseOtSenderOutput, sid, nil, curve, rand, useForcedReuse, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken receiver")
	}

	// Run COTe
	_, round1Output, err := receiver.Round1(choices)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 1")
	}
	_, cOTeSenderOutput, round2Output, err := sender.Round2(round1Output, inputOpts)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken sender round 2")
	}
	cOTeMessage, err = receiver.Round3(round2Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 3")
	}
	return cOTeSenderOutput, cOTeMessage, nil
}

// GenerateSoftspokenRandomInputs generates random inputs for the SoftspokenOT
// Correlated OT extension.
func GenerateSoftspokenRandomInputs(inputBatchLen, scalarsPerSlot int, curve curves.Curve, useForcedReuse bool) (
	choices softspoken.OTeInputChoices, // receiver's input, the Choice bits x
	inputOpts softspoken.COTeMessage, // sender's input, the InputOpt α
	err error,
) {
	if inputBatchLen < 0 {
		return nil, nil, errs.NewInvalidLength("inputBatchLen must be non-negative")
	}
	choicesBatchLen := inputBatchLen // L = inputBatchLen in the general case
	if useForcedReuse {              // L = 1 in the forced reuse case
		choicesBatchLen = 1
	}
	choices = make(softspoken.OTeInputChoices, choicesBatchLen)
	for l := 0; l < choicesBatchLen; l++ {
		if _, err := crand.Read(choices[l][:]); err != nil {
			return nil, nil, errs.WrapRandomSampleFailed(err, "could not generate random choice bits")
		}
	}
	if curve == nil { // Just need the input choices
		return choices, nil, nil
	}
	inputOpts = make(softspoken.COTeMessage, inputBatchLen)
	for l := 0; l < inputBatchLen; l++ {
		for i := 0; i < softspoken.Xi; i++ {
			inputOpts[l][i] = make([]curves.Scalar, scalarsPerSlot)
			for k := 0; k < scalarsPerSlot; k++ {
				inputOpts[l][i][k], err = curve.ScalarField().Random(crand.Reader)
				if err != nil {
					return nil, nil, errs.WrapRandomSampleFailed(err, "could not generate random scalar")
				}
			}
		}
	}
	return choices, inputOpts, nil
}

// CheckSoftspokenCOTeOutputs checks the results of a Correlated OT extension run,
// testing that z_A + z_B = x • α.
func CheckSoftspokenCOTeOutputs(
	cOTeSenderOutputs softspoken.COTeMessage,
	cOTeMessages softspoken.COTeMessage,
	inputOpts softspoken.COTeMessage,
	choices softspoken.OTeInputChoices,
) error {
	L := len(inputOpts)
	useForcedReuse := (len(choices) == 1) && (L > 1)
	scalarsPerSlot := len(inputOpts[0][0])
	// Check length matching
	// require.Equal(t, len(cOTeSenderOutputs), L)
	// require.Equal(t, len(cOTeMessages), L)
	if len(cOTeSenderOutputs) != L || len(cOTeMessages) != L {
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
			x, err := bitstring.SelectBit(choices[idxOTe][:], i)
			if err != nil {
				return errs.WrapFailed(err, "cannot select bit")
			}
			for k := 0; k < scalarsPerSlot; k++ {
				// Check each correlation z_A = x • α - z_B
				z_A := cOTeSenderOutputs[l][i][k]
				z_B := cOTeMessages[l][i][k]
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
