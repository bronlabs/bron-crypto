package testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	ottu "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

func MakeVSOTParticipants(
	senderAuthKey, receiverAuthKey types.AuthKey,
	curve curves.Curve, prng io.Reader, sessionId []byte, transcript transcripts.Transcript,
	Xi, L int,
) (*vsot.Sender, *vsot.Receiver, error) {
	baseSender, baseReceiver, err := ottu.MakeOtParticipants(senderAuthKey, receiverAuthKey, curve, prng, sessionId, transcript, Xi, L)
	// Create vsot participants
	sender, err := vsot.NewSender(baseSender, randomisedFischlin.Name)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in make VSOT participants")
	}
	receiver, err := vsot.NewReceiver(baseReceiver, randomisedFischlin.Name)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT receiver in make VSOT participants")
	}
	return sender, receiver, nil
}

func RunVSOT(sender *vsot.Sender, receiver *vsot.Receiver) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
	r1out, err := sender.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 1 in run VSOT")
	}
	receiversMaskedChoice, err := receiver.Round2(r1out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 2 in run VSOT")
	}
	challenge, err := sender.Round3(receiversMaskedChoice)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 3 in run VSOT")
	}
	challengeResponse, err := receiver.Round4(challenge)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 4 in run VSOT")
	}
	challengeOpenings, err := sender.Round5(challengeResponse)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 5 in run VSOT")
	}
	err = receiver.Round6(challengeOpenings)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 6 in run VSOT")
	}
	return sender.Output, receiver.Output, nil
}

func VSOT(
	senderKey, receiverKey types.AuthKey,
	curve curves.Curve, uniqueSessionId []byte, rng io.Reader,
	Xi, L int,
) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
	sender, receiver, err := MakeVSOTParticipants(senderKey, receiverKey, curve, rng, uniqueSessionId, nil, Xi, L)
	if err != nil {
		return nil, nil, err
	}
	return RunVSOT(sender, receiver)
}
