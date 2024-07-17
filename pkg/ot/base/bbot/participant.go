package bbot

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
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

func sendTo[M any](p2p chan<- ds.Map[types.IdentityKey, M], destination types.IdentityKey, m M) {
	p2pMessage := hashmap.NewHashableHashMap[types.IdentityKey, M]()
	p2pMessage.Put(destination, m)
	p2p <- p2pMessage
}

func receiveFrom[M any](p2p <-chan ds.Map[types.IdentityKey, M], source types.IdentityKey) (M, error) {
	p2pMessage := <-p2p
	m, ok := p2pMessage.Get(source)
	if !ok {
		return *new(M), errs.NewFailed("no message")
	}
	return m, nil
}

func (s *Sender) Run(router roundbased.MessageRouter, r *Receiver) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
	me := s.IdentityKey()
	him := r.IdentityKey()

	r1 := roundbased.NewUnicastRound[*Round1P2P](me, 1, router)
	r2 := roundbased.NewUnicastRound[*Round2P2P](me, 2, router)

	// round 1
	r1Out, err := s.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 1 failed")
	}
	sendTo(r1.UnicastOut(), him, r1Out)

	// round 3
	r3In, err := receiveFrom(r2.UnicastIn(), him)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 3 failed")
	}
	err = s.Round3(r3In)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 3 failed")
	}

	return s.Output, r.Output, nil
}

func (r *Receiver) Run(router roundbased.MessageRouter, s *Sender) error {
	me := r.IdentityKey()
	him := s.IdentityKey()
	r1 := roundbased.NewUnicastRound[*Round1P2P](me, 1, router)
	r2 := roundbased.NewUnicastRound[*Round2P2P](me, 2, router)

	// round 2
	r2In, err := receiveFrom(r1.UnicastIn(), him)
	if err != nil {
		return errs.WrapFailed(err, "round 2 failed")
	}
	r2Out, err := r.Round2(r2In)
	if err != nil {
		return errs.WrapFailed(err, "round 2 failed")
	}
	sendTo(r2.UnicastOut(), him, r2Out)

	return nil
}
