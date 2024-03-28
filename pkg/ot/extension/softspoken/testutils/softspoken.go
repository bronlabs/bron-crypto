package testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

func MakeSoftspokenParticipants(
	senderKey, receiverKey types.AuthKey,
	curve curves.Curve, prng io.Reader, sessionId []byte, transcript transcripts.Transcript,
	baseOtSenderSeeds *ot.SenderRotOutput, baseOtReceiverSeeds *ot.ReceiverRotOutput, prg csprng.CSPRNG, Xi, L int,
) (*softspoken.Sender, *softspoken.Receiver, error) {
	// Create base OT participants
	baseSender, baseReceiver, err := ot_testutils.MakeOtParticipants(senderKey, receiverKey, curve, prng, sessionId, transcript, Xi, L)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create base OT participants")
	}
	// Create softspoken participants
	sender, err := softspoken.NewSoftspokenSender(baseSender, baseOtReceiverSeeds, prg)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken sender")
	}
	receiver, err := softspoken.NewSoftspokenReceiver(baseReceiver, baseOtSenderSeeds, prg)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken receiver")
	}
	return sender, receiver, nil
}

/*.------------------------- Random OT extension ----------------------------.*/

// RunSoftspokenROTe is a utility function encapsulating the entire process of
// running a random OT extension without derandomization.
// As a black box, this function does:
//
//		R: x ---┐                        ┌---> R: (v_x)
//		        ├--- COTe_{Xi,L}(x)---┤
//		S:   ---┘                        └---> S: (v_0, v_1)
//	 s.t. v_x = v_1 • (x) + v_0 • (1-x)
func RunSoftspokenROTe(sender *softspoken.Sender, receiver *softspoken.Receiver, choices ot.PackedBits,
) (oTeSenderOutputs [][2]ot.Message, oTeReceiverOutputs []ot.Message, err error) {
	// Run OTe
	oTeReceiverOutput, r1out, err := receiver.Round1(choices)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 1")
	}
	oTeSenderOutput, err := sender.Round2(r1out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken sender round 2")
	}
	return oTeSenderOutput, oTeReceiverOutput, nil
}

/*.------------------------- Correlated OT extension ------------------------.*/

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
	sender *softspoken.Sender, receiver *softspoken.Receiver,
	choices ot.PackedBits, // receiver's input, the Choice bits x
	senderInput []ot.CorrelatedMessage, // sender's input, the InputOpt batches of α
) (senderOutput, receiverOutput []ot.CorrelatedMessage, err error) {
	// Run COTe
	_, round1Output, err := receiver.Round1(choices)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 1")
	}
	_, err = sender.Round2(round1Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken sender round 2")
	}
	z_A, tau, err := sender.Output.CreateCorrelation(senderInput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 2")
	}
	z_B, err := receiver.Output.ApplyCorrelation(tau)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run softspoken receiver round 3")
	}
	return z_A, z_B, nil
}

/*.--------------------------------------------------------------------------.*/

func SoftspokenROTe(senderKey, receiverKey types.AuthKey,
	curve curves.Curve, prng io.Reader, sessionId []byte, transcript transcripts.Transcript,
	baseOtSenderSeeds *ot.SenderRotOutput, baseOtReceiverSeeds *ot.ReceiverRotOutput, prg csprng.CSPRNG, Xi, L int,
) (oTeSenderOutputs [][2]ot.Message, oTeReceiverChoices ot.PackedBits, oTeReceiverOutputs []ot.Message, err error) {
	sender, receiver, err := MakeSoftspokenParticipants(senderKey, receiverKey, curve, prng, sessionId, transcript, baseOtSenderSeeds, baseOtReceiverSeeds, prg, Xi, L)
	if err != nil {
		return nil, nil, nil, err
	}
	// Generate inputs for ROT
	oTeReceiverChoices, _, err = ot_testutils.GenerateOTinputs(Xi, L)

	// Run ROT
	oTeSenderOutputs, oTeReceiverOutputs, err = RunSoftspokenROTe(sender, receiver, oTeReceiverChoices)
	if err != nil {
		return nil, nil, nil, err
	}
	return oTeSenderOutputs, oTeReceiverChoices, oTeReceiverOutputs, nil
}

func SoftspokenCOTe(senderKey, receiverKey types.AuthKey, curve curves.Curve, prng io.Reader, sessionId []byte, transcript transcripts.Transcript, baseOtSenderSeeds *ot.SenderRotOutput, baseOtReceiverSeeds *ot.ReceiverRotOutput, prg csprng.CSPRNG, Xi, L int) (x ot.PackedBits, a, z_A, z_B []ot.CorrelatedMessage, err error) {
	sender, receiver, err := MakeSoftspokenParticipants(senderKey, receiverKey, curve, prng, sessionId, transcript, baseOtSenderSeeds, baseOtReceiverSeeds, prg, Xi, L)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Generate inputs for COT
	x, a, err = ot_testutils.GenerateCOTinputs(Xi, L, curve)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Run COT
	z_A, z_B, err = RunSoftspokenCOTe(sender, receiver, x, a)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return x, a, z_A, z_B, nil
}
