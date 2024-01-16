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
// RunBaseOT is a utility function encapsulating the entire process of
// running a base OT, so that other tests can use it / bootstrap themselves.
// As a black box, this function uses randomised inputs, and does:
//
//	.             ┌---> R: k^i_{Δ_i}, Δ_i
//	BaseOT_{κ}()--┤
//	.             └---> S: k^i_0, k^i_1
func RunBaseOT(t *testing.T, curve curves.Curve, sid []byte, prng io.Reader) (*vsot.SenderOutput, *vsot.ReceiverOutput, error) {
	t.Helper() // TODO: remove *testing.T from most Run test_util functions. Use errors instead.
	senderOutput, receiverOutput, err := testutils.RunVSOT(t, curve, softspoken.Kappa, sid, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "Base OT run failed")
	}
	return senderOutput, receiverOutput, nil
}

// CheckBaseOTOutputs checks the results of a base OT run, testing
// that k^i_{Δ_i} = k^i_1 • Δ_i + k^i_0 • (1-Δ_i).
func CheckBaseOTOutputs(baseOtSenderOutput *vsot.SenderOutput, baseOtReceiverOutput *vsot.ReceiverOutput) error {
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
	choices softspoken.OTeChoices, // receiver's input, the Choice bits x
	LOTe int, // number of OTe elements per message
	Xi int, // number of OTe messages in the batch
) (oTeSenderOutputs *[2]softspoken.OTeMessageBatch, oTeReceiverOutputs softspoken.OTeMessageBatch, err error) {
	// Setup OTe
	sender, err := softspoken.NewCOtSender(baseOtReceiverOutput, sid, nil, curve, rand, nil, LOTe, Xi)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken sender")
	}
	receiver, err := softspoken.NewCOtReceiver(baseOtSenderOutput, sid, nil, curve, rand, nil, LOTe, Xi)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken receiver")
	}

	// Run OTe
	oTeReceiverOutput, r1out, err := receiver.Round1(choices)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 1")
	}
	oTeSenderOutput, _, _, err := sender.Round2(r1out, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken sender round 2")
	}
	return oTeSenderOutput, oTeReceiverOutput, nil
}

// CheckSoftspokenOTeOutputs checks the results of a random OT extension run,
// testing that v_x = v_1 • x + v_0 • (1-x).
func CheckSoftspokenOTeOutputs(
	oTeSenderOutput *[2]softspoken.OTeMessageBatch, // (v_0, v_1)
	oTeReceiverOutput softspoken.OTeMessageBatch, // (v_x)
	choices softspoken.OTeChoices, // (x)
	LOTe int, // number of OTe elements per message
	Xi int, // number of OTe messages in the batch
) error {
	// Check length matching
	if len(oTeSenderOutput[0]) != Xi || len(oTeSenderOutput[1]) != Xi || len(oTeReceiverOutput) != Xi {
		return errs.NewInvalidLength("OTe input/output batch length mismatch")
	}
	messageLength := LOTe * softspoken.KappaBytes
	for j := 0; j < Xi; j++ {
		if len(oTeReceiverOutput[j]) != messageLength || len(oTeSenderOutput[0][j]) != messageLength || len(oTeSenderOutput[1][j]) != messageLength {
			return errs.NewInvalidLength("OTe output message length mismatch")
		}
	}
	// Check OTe results
	for j := 0; j < Xi; j++ {
		// Check that v_x = v_1 • x + v_0 • (1-x)
		xBit, err := bitstring.SelectBit(choices, j)
		if err != nil {
			return errs.WrapFailed(err, "cannot select bit")
		}
		if !bytes.Equal(oTeSenderOutput[xBit][j], oTeReceiverOutput[j]) {
			return errs.NewVerificationFailed("OTe output mismatch for index %d", j)
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
	curve curves.Curve,
	sid []byte,
	rand io.Reader,
	baseOtSenderOutput *vsot.SenderOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *vsot.ReceiverOutput, // baseOT seeds for OTe sender
	choices softspoken.OTeChoices, // receiver's input, the Choice bits x
	senderInput softspoken.COTeMessageBatch, // sender's input, the InputOpt batches of α
	LOTe int, // number of OTe elements per message
	Xi int, // number of OTe messages in the batch
) (senderOutput, receiverOutput softspoken.COTeMessageBatch, err error) {
	// Setup COTe
	sender, err := softspoken.NewCOtSender(baseOtReceiverOutput, sid, nil, curve, rand, nil, LOTe, Xi)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken sender")
	}
	receiver, err := softspoken.NewCOtReceiver(baseOtSenderOutput, sid, nil, curve, rand, nil, LOTe, Xi)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken receiver")
	}

	// Run COTe
	_, round1Output, err := receiver.Round1(choices)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 1")
	}
	_, senderOutput, round2Output, err := sender.Round2(round1Output, senderInput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken sender round 2")
	}
	receiverOutput, err = receiver.Round3(round2Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 3")
	}
	return senderOutput, receiverOutput, nil
}

// GenerateSoftspokenRandomInputs generates random inputs for the SoftspokenOT
// Correlated OT extension.
func GenerateSoftspokenRandomInputs(curve curves.Curve, LOTe, Xi int) (
	choices softspoken.OTeChoices, // receiver's input, the Choice bits x
	inputMessageBatch softspoken.COTeMessageBatch, // sender's input, the InputOpt α
	err error,
) {
	if LOTe < 1 || Xi < 1 {
		return nil, nil, errs.NewInvalidLength(" cannot generate random inputs for LOTe=%d, Xi=%d", LOTe, Xi)
	}
	choices = make(softspoken.OTeChoices, Xi/8)
	if _, err := crand.Read(choices); err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "could not generate random choice bits")
	}
	if curve == nil { // Just need the input choices
		return choices, nil, nil
	}
	inputMessageBatch = make(softspoken.COTeMessageBatch, Xi)
	for j := 0; j < Xi; j++ {
		inputMessageBatch[j] = make(softspoken.COTeMessage, LOTe)
		for l := 0; l < LOTe; l++ {
			inputMessageBatch[j][l], err = curve.Scalar().ScalarField().Random(crand.Reader)
			if err != nil {
				return nil, nil, errs.WrapRandomSampleFailed(err, "could not generate random scalar")
			}
		}
	}
	return choices, inputMessageBatch, nil
}

// CheckSoftspokenCOTeOutputs checks the results of a Correlated OT extension run,
// testing that z_A + z_B = x • α.
func CheckSoftspokenCOTeOutputs(
	receiverChoices softspoken.OTeChoices, // (x)
	senderInput softspoken.COTeMessageBatch, // (α)
	receiverOutput softspoken.COTeMessageBatch, // (z_B)
	senderOutput softspoken.COTeMessageBatch, // (z_A)
	LOTe int, // number of OTe elements per message
	Xi int, // number of OTe messages in the batch
) error {
	if len(receiverChoices)*8 != Xi || len(receiverOutput) != Xi || len(senderOutput) != Xi || len(senderInput) != Xi {
		return errs.NewInvalidLength("COTe input/output batch length mismatch (%d, %d, %d, %d, %d)",
			Xi, len(receiverChoices)*8, len(receiverOutput), len(senderOutput), len(senderInput))
	}
	// Check correlation in COTe results
	for j := 0; j < Xi; j++ {
		if len(receiverOutput[j]) != LOTe || len(senderOutput[j]) != LOTe || len(senderInput[j]) != LOTe {
			return errs.NewInvalidLength("COTe input/output message %d length mismatch (should be %d, is: %d, %d, %d)",
				j, LOTe, len(receiverOutput[j]), len(senderOutput[j]), len(senderInput[j]))
		}
		x, err := bitstring.SelectBit(receiverChoices, j)
		if err != nil {
			return errs.WrapFailed(err, "cannot select bit")
		}
		for l := 0; l < LOTe; l++ {
			// Check each correlation z_A = x • α - z_B
			z_A := senderOutput[j][l]
			z_B := receiverOutput[j][l]
			alpha := senderInput[j][l]
			if x != 0 {
				if z_A.Cmp(alpha.Sub(z_B)) != 0 {
					return errs.NewVerificationFailed("COTe output mismatch for index %d", j)
				}
			} else {
				if z_A.Cmp(z_B.Neg()) != 0 {
					return errs.NewVerificationFailed("COTe output mismatch for index %d", j)
				}
			}
		}
	}
	return nil
}
