package bbot

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

const transcriptLabel = "COPPER_KRYPTON_BBOT-"

// Sender obtains the 2 random messages for the 1|2 ROT.
type Sender struct {
	ot.Participant

	Output *ot.SenderRotOutput // (s_0, s_1) ∈ [ξ][2][L][κ]bits, the batch of 2 L×κ-bit messages of the 1|2 ROT.

	MyEsk curves.Scalar // MyEsk is my ephemeral secret key.
}

// Receiver chooses one message (with its choice bit) out of the sender's 1|2 ROT messages.
type Receiver struct {
	ot.Participant

	Output *ot.ReceiverRotOutput // (x ∈[ξ]bits, r_x ∈[ξ][L][κ]bits), the batches of choice bits and chosen L×κ-bit messages of the 1|2 ROT.

	MyEsk curves.Scalar // MyEsk is my ephemeral secret key.
}

// NewSender constructs a Random OT sender.
func NewSender(baseParticipant types.Participant[ot.Protocol]) (*Sender, error) {
	participant, err := ot.NewParticipant(baseParticipant, transcriptLabel, 1)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing sender")
	}
	return &Sender{
		Output:      &ot.SenderRotOutput{},
		Participant: *participant,
	}, nil
}

// NewReceiver constructs a Random OT receiver.
func NewReceiver(baseParticipant types.Participant[ot.Protocol]) (*Receiver, error) {
	participant, err := ot.NewParticipant(baseParticipant, transcriptLabel, 2)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing receiver")
	}

	choices := make(ot.PackedBits, participant.Protocol().Xi()/8)
	if _, err := io.ReadFull(participant.Prng(), choices); err != nil {
		return nil, errs.WrapRandomSample(err, "generating random choice bits")
	}

	return &Receiver{
		Output:      &ot.ReceiverRotOutput{Choices: choices},
		Participant: *participant,
	}, nil
}
