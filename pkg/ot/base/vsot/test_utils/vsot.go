package test_utils

import (
	"io"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
)

// RunVSOT is a utility function used _only_ during various tests.
// essentially, it encapsulates the entire process of running a base OT, so that other tests can use it / bootstrap themselves.
// it handles the creation of the base OT sender and receiver, as well as orchestrates the rounds on them;
// it returns their outsputs, so that others can use them.
func RunVSOT(t *testing.T, curve curves.Curve, batchSize int, uniqueSessionId []byte, prng io.Reader) (*vsot.SenderOutput, *vsot.ReceiverOutput, error) {
	t.Helper()
	receiver, err := vsot.NewReceiver(curve, batchSize, uniqueSessionId, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT receiver in run VSOT")
	}
	sender, err := vsot.NewSender(curve, batchSize, uniqueSessionId, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in run VSOT")
	}
	proof, publicKey, err := sender.Round1ComputeAndZkpToPublicKey()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 1 in run VSOT")
	}
	receiversMaskedChoice, err := receiver.Round2VerifySchnorrAndPadTransfer(publicKey, proof)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 2 in run VSOT")
	}
	challenge, err := sender.Round3PadTransfer(receiversMaskedChoice)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 3 in run VSOT")
	}
	challengeResponse, err := receiver.Round4RespondToChallenge(challenge)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 4 in run VSOT")
	}
	challengeOpenings, err := sender.Round5Verify(challengeResponse)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 5 in run VSOT")
	}
	err = receiver.Round6Verify(challengeOpenings)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 6 in run VSOT")
	}
	return sender.Output, receiver.Output, nil
}
