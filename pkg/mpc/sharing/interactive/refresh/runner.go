package refresh

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "RefreshRound1"
)

type refreshRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant *Participant[G, S]
}

func NewRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](sid network.SID, shard *tsig.BaseShard[G, S], tape transcripts.Transcript, prng io.Reader) (network.Runner[*Output[G, S]], error) {
	participant, err := NewParticipant(sid, shard, tape, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}

	runner := &refreshRunner[G, S]{
		participant: participant,
	}
	return runner, nil
}

func (r *refreshRunner[G, S]) Run(rt *network.Router) (*Output[G, S], error) {
	r1bOut, r1uOut, err := r.participant.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r1bIn, r1uIn, err := exchange.Exchange(rt, r1CorrelationID, r.participant.shard.AccessStructure().Shareholders(), r1bOut, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}

	output, err := r.participant.Round2(r1bIn, r1uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}

	return output, nil
}
