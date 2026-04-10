package recovery

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
)

const (
	r1CorrelationID = "RecoveryRound1"
	r2CorrelationID = "RecoveryRound2"
)

type recovererRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	party *Recoverer[G, S]
}

type mislayerRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	party *Mislayer[G, S]
}

func NewRecovererRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, mislayerID sharing.ID, baseShard *tsig.BaseShard[G, S], prng io.Reader) (network.Runner[any], error) {
	party, err := NewRecoverer(ctx, mislayerID, baseShard, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create recoverer")
	}
	r := &recovererRunner[G, S]{
		party: party,
	}
	return r, nil
}

// NewMislayerRunner constructs a network runner that drives the three DKG rounds.
func NewMislayerRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, as *threshold.Threshold, group algebra.PrimeGroup[G, S]) (network.Runner[*Output[G, S]], error) {
	party, err := NewMislayer(ctx, as, group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create mislayer")
	}
	r := &mislayerRunner[G, S]{
		party: party,
	}
	return r, nil
}

func (r *recovererRunner[G, S]) Run(rt *network.Router) (any, error) {
	r1bOut, r1uOut, err := r.party.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r1bIn, r2uIn, err := exchange.Exchange(rt, r1CorrelationID, r.party.recoverersCtx.Quorum(), r1bOut, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange r1 messages")
	}

	r2Out, err := r.party.Round2(r1bIn, r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	err = exchange.UnicastSend(rt, r2CorrelationID, r2Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot send round 2")
	}

	//nolint:nilnil // no void type in go
	return nil, nil
}

// Run executes the recovery rounds using the provided router and returns the final output.
func (r *mislayerRunner[G, S]) Run(rt *network.Router) (*Output[G, S], error) {
	recoverers := hashset.NewComparable(r.party.ctx.Quorum().List()...)
	recoverers.Remove(r.party.ctx.HolderID())
	r2, err := exchange.UnicastReceive[*Round2P2P[G, S]](rt, r2CorrelationID, recoverers.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot receive round 2")
	}
	output, err := r.party.Round3(r2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}

	return output, nil
}
