package bbot_testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

/*.------------------------------ PARTICIPANTS ------------------------------.*/

// CreateParticipants creates the sender and receiver for the batched base OT protocol.
func CreateParticipants(
	scenario *ot_testutils.OtScenario, rng io.Reader,
	otParamsSender *ot_testutils.OtParams,
	otParamsReceiver *ot_testutils.OtParams,
) (*bbot.Sender, *bbot.Receiver, error) {
	participants := hashset.NewHashableHashSet(scenario.SenderKey.(types.IdentityKey), scenario.ReceiverKey.(types.IdentityKey))
	senderProtocol, err := types.NewProtocol(otParamsSender.Curve, participants)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct ot protocol config")
	}
	sender, err := bbot.NewSender(scenario.SenderKey, senderProtocol, otParamsSender.Xi, otParamsSender.L, otParamsSender.SessionId, nil, rng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in run BatchedBaseOT")
	}
	receiverProtocol, err := types.NewProtocol(otParamsReceiver.Curve, participants)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct ot protocol config")
	}
	receiver, err := bbot.NewReceiver(scenario.ReceiverKey, receiverProtocol, otParamsReceiver.Xi, otParamsReceiver.L, otParamsReceiver.SessionId, nil, rng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT receiver in run BatchedBaseOT")
	}
	return sender, receiver, nil
}

/*.----------------------------- PROTOCOL RUNS ------------------------------.*/

// RunROT runs the batched base OT protocol with random sender inputs (ROT functionality).
func RunROT(
	sender *bbot.Sender, receiver *bbot.Receiver,
	receiverChoices ot.PackedBits,
) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error,
) {
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

// RunAllOTs runs all three functionaloties (ROT, OT, COT) for the batched base OT protocol.
func RunAllOTs(
	sender *bbot.Sender, receiver *bbot.Receiver,
	receiverInputChoices ot.PackedBits,
) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, [][2]ot.Message, []ot.Message, []ot.CorrelatedMessage, []ot.CorrelatedMessage, []ot.CorrelatedMessage, error,
) {
	// ROT
	receiverInput, senderOtInput, err := ot_testutils.GenerateInputsOT(sender.Protocol.Xi, sender.Protocol.L)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errs.WrapFailed(err, "could not generate inputs for OT")
	}
	if receiverInputChoices != nil {
		receiverInput = receiverInputChoices
	}
	senderRotOutput, receiverRotOutput, err := RunROT(sender, receiver, receiverInput)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errs.WrapFailed(err, "could not run BBOT_ROT")
	}

	// OT
	masks, err := senderRotOutput.Encrypt(senderOtInput)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errs.WrapFailed(err, "could not encrypt OT")
	}
	receiverOtOutput, err := receiverRotOutput.Decrypt(masks)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errs.WrapFailed(err, "could not decrypt OT")
	}

	// COT
	_, a, err := ot_testutils.GenerateInputsCOT(sender.Protocol.Xi, sender.Protocol.L, sender.Protocol.Curve())
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errs.WrapFailed(err, "could not generate inputs for COT")
	}
	z_A, tau, err := senderRotOutput.CreateCorrelation(a)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errs.WrapFailed(err, "could not create correlation for COT")
	}
	z_B, err := receiverRotOutput.ApplyCorrelation(tau)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errs.WrapFailed(err, "could not apply correlation for COT")
	}
	return senderRotOutput, receiverRotOutput, senderOtInput, receiverOtOutput, a, z_A, z_B, nil
}

func RunROT_Reuse(sender *bbot.Sender, receiver *bbot.Receiver, reuseParams *ot_testutils.ReuseParams,
) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
	reuseRound := reuseParams.ReuseRound%2 + 1 // 1 or 2

	// First run
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

	// Second run
	var r1OutLater *bbot.Round1P2P
	if reuseRound == 1 {
		r1OutLater = r1Out
	} else {
		r1OutLater, err = sender.Round1()
	}
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 1 in run BatchedBaseOT second run")
	}

	var r2OutLater *bbot.Round2P2P
	if reuseRound == 2 {
		r2OutLater = r2Out
	} else {
		r2OutLater, err = receiver.Round2(r1OutLater)
	}

	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 2 in run BatchedBaseOT second run")
	}
	err = sender.Round3(r2OutLater)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 3 in run BatchedBaseOT second run")
	}
	return sender.Output, receiver.Output, nil
}

/*.------------------------------- PIPELINED --------------------------------.*/

func PipelineRunROT(senderKey, receiverKey types.AuthKey, batchSize, messageLength int, curve curves.Curve, uniqueSessionId []byte, rng io.Reader) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
	pp := &ot_testutils.OtParams{
		Xi:        batchSize,
		L:         messageLength,
		Curve:     curve,
		SessionId: uniqueSessionId,
	}
	sender, receiver, err := CreateParticipants(&ot_testutils.OtScenario{
		SenderKey:   senderKey,
		ReceiverKey: receiverKey,
	}, rng, pp, pp)
	if err != nil {
		return nil, nil, err
	}
	return RunROT(sender, receiver, nil)
}
