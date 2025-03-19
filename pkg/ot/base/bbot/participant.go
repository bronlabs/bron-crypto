package bbot

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const transcriptLabel = "BRON_CRYPTO_BBOT-"

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
func NewSender(myAuthKey types.AuthKey, protocol types.Protocol, Xi, L int, sessionId []byte, transcript transcripts.Transcript, csprng io.Reader) (*Sender, error) {
	participant, err := ot.NewParticipant(myAuthKey, protocol, Xi, L, sessionId, transcriptLabel, transcript, csprng, 1)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing sender")
	}
	return &Sender{
		Output:      &ot.SenderRotOutput{},
		Participant: *participant,
	}, nil
}

// NewReceiver constructs a Random OT receiver.
func NewReceiver(myAuthKey types.AuthKey, protocol types.Protocol, Xi, L int, sessionId []byte, transcript transcripts.Transcript, csprng io.Reader) (*Receiver, error) {
	participant, err := ot.NewParticipant(myAuthKey, protocol, Xi, L, sessionId, transcriptLabel, transcript, csprng, 2)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing receiver")
	}

	choices := make(ot.PackedBits, Xi/8)
	if _, err := io.ReadFull(csprng, choices); err != nil {
		return nil, errs.WrapRandomSample(err, "generating random choice bits")
	}

	return &Receiver{
		Output:      &ot.ReceiverRotOutput{Choices: choices},
		Participant: *participant,
	}, nil
}
