package ecbbot

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const transcriptLabel = "BRON_CRYPTO_BBOT-"

type participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ka    *TaggedKeyAgreement[G, S]
	suite *Suite[G, S]
	round int
	tape  transcripts.Transcript
	prng  io.Reader
}

// Sender obtains the 2 random messages for the 1|2 ROT.
type Sender[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant[G, S]

	state SenderState[S]
}

type SenderState[S algebra.PrimeFieldElement[S]] struct {
	a S
}

// Receiver chooses one message (with its choice bit) out of the sender's 1|2 ROT messages.
type Receiver[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant[G, S]
}

// NewSender constructs a Random OT sender.
func NewSender[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](sessionID network.SID, suite *Suite[G, S], tape transcripts.Transcript, prng io.Reader) (*Sender[G, S], error) {
	if suite == nil || tape == nil || prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid args")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	ka, err := NewTaggedKeyAgreement(suite.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create tagged key agreement")
	}

	s := &Sender[G, S]{
		participant: participant[G, S]{
			ka:    ka,
			round: 1,
			suite: suite,
			tape:  tape,
			prng:  prng,
		},
		state: SenderState[S]{}, //nolint:exhaustruct // zero value, populated during protocol
	}

	return s, nil
}

// NewReceiver constructs a Random OT receiver.
func NewReceiver[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](sessionID network.SID, suite *Suite[G, S], tape transcripts.Transcript, prng io.Reader) (*Receiver[G, S], error) {
	if suite == nil || tape == nil || prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid args")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	ka, err := NewTaggedKeyAgreement(suite.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create tagged key agreement")
	}

	r := &Receiver[G, S]{
		participant: participant[G, S]{
			ka:    ka,
			suite: suite,
			round: 2,
			tape:  tape,
			prng:  prng,
		},
	}
	return r, nil
}
