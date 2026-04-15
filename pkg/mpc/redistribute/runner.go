package redistribute

import (
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
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
	r2CorrelationID = "RedistributeRound2"
)

type runner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant *Participant[G, S]
}

// NewRunner constructs a network runner that executes the redistribution
// protocol.
func NewRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, trustedDealerID sharing.ID, recoverers ds.Set[sharing.ID], prevShard *mpc.BaseShard[G, S], nextAccessStructure accessstructures.Monotone, prng io.Reader) (network.Runner[*mpc.BaseShard[G, S]], error) {
	participant, err := NewParticipant(ctx, trustedDealerID, recoverers, prevShard, nextAccessStructure, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}

	return &runner[G, S]{
		participant: participant,
	}, nil
}

// Run executes the redistribution rounds over the provided router.
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
	r1uIn := hashmap.NewComparable[sharing.ID, *Round1P2P[G, S]]().Freeze()
	if r.participant.isPrevShareholder(r.participant.ctx.HolderID()) {
		r1uIn, err = exchange.UnicastReceive[*Round1P2P[G, S], *Participant[G, S]](rt, r1CorrelationID, prevSenders)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot receive round 1 p2p")
		}
	}
	r2bOut, r2uOut, err := r.participant.Round2(r1bIn, r1uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}

	r2bIn, err := exchange.BroadcastExchange(rt, r2CorrelationID, r.participant.ctx.Quorum(), r2bOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 broadcast")
	}
	if r2uOut != nil {
		err = exchange.UnicastSend(rt, r2CorrelationID, r2uOut)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot send round 2 p2p")
		}
	}

	// r3
	r2uIn := hashmap.NewComparable[sharing.ID, *Round2P2P[G, S]]().Freeze()
	if r.participant.isNextShareholder(r.participant.ctx.HolderID()) {
		r2uIn, err = exchange.UnicastReceive[*Round2P2P[G, S], *Participant[G, S]](rt, r2CorrelationID, prevSenders)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot receive round 2 p2p")
		}
	}
	output, err := r.participant.Round3(r2bIn, r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}

	return output, nil
}
