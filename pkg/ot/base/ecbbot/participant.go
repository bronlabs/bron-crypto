package ecbbot

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const transcriptLabel = "BRON_CRYPTO_BBOT-"

type Participant[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	group algebra.PrimeGroup[GE, SE]
	ka    *TaggedKeyAgreement[GE, SE]
	round int
	tape  transcripts.Transcript
	prng  io.Reader
	chi   int
	l     int
}

// Sender obtains the 2 random messages for the 1|2 ROT.
type Sender[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	Participant[GE, SE]

	State SenderState[SE]
}

type SenderState[SE algebra.PrimeFieldElement[SE]] struct {
	A SE
}

// Receiver chooses one message (with its choice bit) out of the sender's 1|2 ROT messages.
type Receiver[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	Participant[GE, SE]
}

// NewSender constructs a Random OT sender.
func NewSender[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](sessionId network.SID, group algebra.PrimeGroup[GE, SE], chi, l int, tape transcripts.Transcript, prng io.Reader) (*Sender[GE, SE], error) {
	// TODO: input validation

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	ka, err := NewTaggedKeyAgreement(group)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create tagged key agreement")
	}

	s := &Sender[GE, SE]{
		Participant: Participant[GE, SE]{
			group: group,
			ka:    ka,
			round: 1,
			tape:  tape,
			prng:  prng,
			chi:   chi,
			l:     l,
		},
	}

	return s, nil
}

// NewReceiver constructs a Random OT receiver.
func NewReceiver[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](sessionId network.SID, group algebra.PrimeGroup[GE, SE], chi, l int, tape transcripts.Transcript, prng io.Reader) (*Receiver[GE, SE], error) {
	// TODO input validation

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	ka, err := NewTaggedKeyAgreement(group)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create tagged key agreement")
	}

	r := &Receiver[GE, SE]{
		Participant: Participant[GE, SE]{
			group: group,
			ka:    ka,
			round: 2,
			tape:  tape,
			prng:  prng,
			chi:   chi,
			l:     l,
		},
	}
	return r, nil
}
