package test_utils

import (
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/vsot"
)

// RunVSOT is a utility function used _only_ during various tests.
// essentially, it encapsulates the entire process of running a base OT, so that other tests can use it / bootstrap themselves.
// it handles the creation of the base OT sender and receiver, as well as orchestrates the rounds on them;
// it returns their outsputs, so that others can use them.
func RunVSOT(t *testing.T, curve *curves.Curve, batchSize int, uniqueSessionId []byte) (*vsot.SenderOutput, *vsot.ReceiverOutput, error) {
	t.Helper()
	receiver, err := vsot.NewReceiver(curve, batchSize, uniqueSessionId, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT receiver in run simplest OT")
	}
	sender, err := vsot.NewSender(curve, batchSize, uniqueSessionId, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in run simplest OT")
	}
	proof, err := sender.Round1ComputeAndZkpToPublicKey()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 1 in run simplest OT")
	}
	receiversMaskedChoice, err := receiver.Round2VerifySchnorrAndPadTransfer(proof)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 2 in run simplest OT")
	}
	challenge, err := sender.Round3PadTransfer(receiversMaskedChoice)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 3 in run simplest OT")
	}
	challengeResponse := receiver.Round4RespondToChallenge(challenge)
	challengeOpenings, err := sender.Round5Verify(challengeResponse)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 5 in run simplest OT")
	}
	err = receiver.Round6Verify(challengeOpenings)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 6 in run simplest OT")
	}
	return sender.Output, receiver.Output, nil
}
