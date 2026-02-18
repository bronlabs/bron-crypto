package dkg

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "DKLS23DKGRound1"
	r2CorrelationID = "DKLS23DKGRound2"
	r3CorrelationID = "DKLS23DKGRound3"
	r4CorrelationID = "DKLS23DKGRound4"
	r5CorrelationID = "DKLS23DKGRound5"
)

type dkgRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant *Participant[P, B, S]
}

func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	sessionID network.SID,
	sharingID sharing.ID,
	baseShard *tecdsa.Shard[P, B, S],
	tape transcripts.Transcript,
	prng io.Reader,
) (network.Runner[*dkls23.Shard[P, B, S]], error) {
	participant, err := NewParticipant(sessionID, sharingID, baseShard, tape, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}
	return &dkgRunner[P, B, S]{participant: participant}, nil
}

func (r *dkgRunner[P, B, S]) Run(rt *network.Router) (*dkls23.Shard[P, B, S], error) {
	quorum := r.participant.baseShard.AccessStructure().Shareholders()

	r1bOut, r1uOut, err := r.participant.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2bIn, r2uIn, err := exchange.Exchange(rt, r1CorrelationID, quorum, r1bOut, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}

	r2uOut, err := r.participant.Round2(r2bIn, r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3uIn, err := exchange.UnicastExchange(rt, r2CorrelationID, r2uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}

	r3uOut, err := r.participant.Round3(r3uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	r4uIn, err := exchange.UnicastExchange(rt, r3CorrelationID, r3uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 messages")
	}

	r4uOut, err := r.participant.Round4(r4uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	r5uIn, err := exchange.UnicastExchange(rt, r4CorrelationID, r4uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 4 messages")
	}

	r5uOut, err := r.participant.Round5(r5uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 5")
	}
	r6uIn, err := exchange.UnicastExchange(rt, r5CorrelationID, r5uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 5 messages")
	}

	shard, err := r.participant.Round6(r6uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 6")
	}
	return shard, nil
}
