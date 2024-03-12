package testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
)

/*.------------------------- Random OT extension ----------------------------.*/

// RunSoftspokenROTe is a utility function encapsulating the entire process of
// running a random OT extension without derandomization.
// As a black box, this function does:
//
//		R: x ---┐                        ┌---> R: (v_x)
//		        ├--- COTe_{Xi,L}(x)---┤
//		S:   ---┘                        └---> S: (v_0, v_1)
//	 s.t. v_x = v_1 • (x) + v_0 • (1-x)
func RunSoftspokenROTe(
	senderKey, receiverKey types.AuthKey,
	Xi int, // number of OTe messages in the batch
	L int, // number of OTe elements per message
	curve curves.Curve,
	sid []byte,
	rand io.Reader,
	baseOtSenderOutput *ot.SenderRotOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *ot.ReceiverRotOutput, // baseOT seeds for OTe sender
	choices ot.ChoiceBits, // receiver's input, the Choice bits x
) (oTeSenderOutputs []ot.MessagePair, oTeReceiverOutputs []ot.ChosenMessage, err error) {
	protocol, err := types.NewMPCProtocol(curve, hashset.NewHashableHashSet(senderKey.(types.IdentityKey), receiverKey.(types.IdentityKey)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct ot protocol config")
	}
	// Setup OTe
	sender, err := softspoken.NewSoftspokenSender(senderKey, protocol, baseOtReceiverOutput, sid, nil, rand, nil, L, Xi)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken sender")
	}
	receiver, err := softspoken.NewSoftspokenReceiver(receiverKey, protocol, baseOtSenderOutput, sid, nil, rand, nil, L, Xi)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken receiver")
	}

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
	senderKey, receiverKey types.AuthKey,
	curve curves.Curve,
	sid []byte,
	rand io.Reader,
	baseOtSenderOutput *ot.SenderRotOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *ot.ReceiverRotOutput, // baseOT seeds for OTe sender
	choices ot.ChoiceBits, // receiver's input, the Choice bits x
	senderInput []ot.CorrelatedMessage, // sender's input, the InputOpt batches of α
	L int, // number of OTe elements per message
	Xi int, // number of OTe messages in the batch
) (senderOutput, receiverOutput []ot.CorrelatedMessage, err error) {
	protocol, err := types.NewMPCProtocol(curve, hashset.NewHashableHashSet(senderKey.(types.IdentityKey), receiverKey.(types.IdentityKey)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct ot protocol config")
	}
	// Setup COTe
	sender, err := softspoken.NewSoftspokenSender(senderKey, protocol, baseOtReceiverOutput, sid, nil, rand, nil, L, Xi)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken sender")
	}
	receiver, err := softspoken.NewSoftspokenReceiver(receiverKey, protocol, baseOtSenderOutput, sid, nil, rand, nil, L, Xi)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create softspoken receiver")
	}

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
