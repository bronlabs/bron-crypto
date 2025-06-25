package ecbbot

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const transcriptLabel = "BRON_CRYPTO_BBOT-"

type Participant struct {
	ot.Participant
	ka *TaggedKeyAgreement
}

// Sender obtains the 2 random messages for the 1|2 ROT.
type Sender struct {
	Participant

	State SenderState
}

type SenderState struct {
	A curves.Scalar
}

// Receiver chooses one message (with its choice bit) out of the sender's 1|2 ROT messages.
type Receiver struct {
	Participant
}

// NewSender constructs a Random OT sender.
func NewSender(myAuthKey types.AuthKey, protocol types.Protocol, Xi, L int, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (*Sender, error) {
	participant, err := ot.NewParticipant(myAuthKey, protocol, Xi, L, sessionId, transcriptLabel, transcript, prng, 1)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing sender")
	}

	ka, err := NewTaggedKeyAgreement(protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create tagged key agreement")
	}

	s := &Sender{
		Participant: Participant{
			Participant: *participant,
			ka:          ka,
		},
	}

	return s, nil
}

// NewReceiver constructs a Random OT receiver.
func NewReceiver(myAuthKey types.AuthKey, protocol types.Protocol, Xi, L int, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (*Receiver, error) {
	participant, err := ot.NewParticipant(myAuthKey, protocol, Xi, L, sessionId, transcriptLabel, transcript, prng, 2)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing receiver")
	}

	ka, err := NewTaggedKeyAgreement(protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create tagged key agreement")
	}

	r := &Receiver{
		Participant: Participant{
			Participant: *participant,
			ka:          ka,
		},
	}
	return r, nil
}
