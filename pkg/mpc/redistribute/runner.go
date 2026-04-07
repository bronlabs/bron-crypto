package redistribute

import (
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
)

const (
	r1CorrelationID = "RedistributeRound1"
)

type runner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant *Participant[G, S]
}

// NewRunner constructs a network runner that executes the redistribution
// protocol.
func NewRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, recoverers ds.Set[sharing.ID], prevShard *mpc.BaseShard[G, S], nextAccessStructure accessstructures.Monotone, prng io.Reader) (network.Runner[*mpc.BaseShard[G, S]], error) {
	participant, err := NewParticipant(ctx, recoverers, prevShard, nextAccessStructure, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}

	return &runner[G, S]{
		participant: participant,
	}, nil
}

// Run executes the two redistribution rounds over the provided router.
func (r *runner[G, S]) Run(rt *network.Router) (*mpc.BaseShard[G, S], error) {
	// r1
	r1bOut, r1uOut, err := r.participant.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r1bIn, err := exchange.BroadcastExchange(rt, r1CorrelationID, r.participant.ctx.Quorum(), r1bOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 broadcast")
	}
	if r1uOut != nil {
		err = exchange.UnicastSend(rt, r1CorrelationID, r1uOut)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot send round 1 p2p")
		}
	}

	// r2
	prevSenders := hashset.NewComparable(slices.Collect(r.participant.otherPrevShareholders())...).Freeze()
	r1uIn, err := exchange.UnicastReceive[*Round1P2P[G, S], *Participant[G, S]](rt, r1CorrelationID, prevSenders)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot receive round 1 p2p")
	}
	output, err := r.participant.Round2(r1bIn, r1uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}

	return output, nil
}
