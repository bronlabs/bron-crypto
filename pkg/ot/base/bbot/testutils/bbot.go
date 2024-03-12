package testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
)

// RunBBOT runs the full batched base OT protocol.
func RunBBOT(senderAuthKey, receiverAuthKey types.AuthKey, Xi, L int, curve curves.Curve, uniqueSessionId []byte, prng io.Reader) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
	protocol, err := types.NewMPCProtocol(curve, hashset.NewHashableHashSet(senderAuthKey.(types.IdentityKey), receiverAuthKey.(types.IdentityKey)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct ot protocol config")
	}
	// Create participants
	sender, err := bbot.NewSender(senderAuthKey, protocol, Xi, L, uniqueSessionId, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in run BatchedBaseOT")
	}
	receiver, err := bbot.NewReceiver(receiverAuthKey, protocol, Xi, L, uniqueSessionId, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT receiver in run BatchedBaseOT")
	}

	// Run the protocol
	r1Out, err := sender.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 1 in run BatchedBaseOT")
	}
	r2Out, err := receiver.Round2(r1Out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 2 in run BatchedBaseOT")
	}
	err = sender.Round3(r2Out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 3 in run BatchedBaseOT")
	}
	return sender.Output, receiver.Output, nil
}
