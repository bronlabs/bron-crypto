package testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
)

func RunVSOT(senderAuthKey, receiverAuthKey types.AuthKey, batchSize, messageLength int, curve curves.Curve, uniqueSessionId []byte, prng io.Reader) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
	protocol, err := types.NewMPCProtocol(curve, hashset.NewHashableHashSet(senderAuthKey.(types.IdentityKey), receiverAuthKey.(types.IdentityKey)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct ot protocol config")
	}
	receiver, err := vsot.NewReceiver(receiverAuthKey, protocol, batchSize, messageLength, uniqueSessionId, randomisedFischlin.Name, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT receiver in run VSOT")
	}
	sender, err := vsot.NewSender(senderAuthKey, protocol, batchSize, messageLength, uniqueSessionId, randomisedFischlin.Name, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in run VSOT")
	}
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
