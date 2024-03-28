package testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	ottu "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

// MakeBBOTParticipants creates the participants for the BBOT protocol.
func MakeBBOTParticipants(senderAuthKey, receiverAuthKey types.AuthKey, curve curves.Curve, prng io.Reader, sessionId []byte, transcript transcripts.Transcript, Xi, L int) (*bbot.Sender, *bbot.Receiver, error) {
	baseSender, baseReceiver, err := ottu.MakeOtParticipants(senderAuthKey, receiverAuthKey, curve, prng, sessionId, transcript, Xi, L)
	// Create bbot participants
	oTsender, err := bbot.NewSender(baseSender)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in make BBOT participants")
	}
	oTreceiver, err := bbot.NewReceiver(baseReceiver)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT receiver in make BBOT participants")
	}
	return oTsender, oTreceiver, nil
}

// RunBBOT runs the full batched base OT protocol.
func RunBBOT(sender *bbot.Sender, receiver *bbot.Receiver) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
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

func BBOT(senderKey, receiverKey types.AuthKey, curve curves.Curve, uniqueSessionId []byte, rng io.Reader, Xi, L int) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
	sender, receiver, err := MakeBBOTParticipants(senderKey, receiverKey, curve, rng, uniqueSessionId, nil, Xi, L)
	if err != nil {
		return nil, nil, err
	}
	return RunBBOT(sender, receiver)
}
