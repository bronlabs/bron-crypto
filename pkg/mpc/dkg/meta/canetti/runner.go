package canetti

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "BRON_CRYPTO_DKG_CANETTI_R1"
	r2CorrelationID = "BRON_CRYPTO_DKG_CANETTI_R2"
	r3CorrelationID = "BRON_CRYPTO_DKG_CANETTI_R3"
)

func _[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]]() {
	var _ network.Runner[*mpc.BaseShard[G, S]] = (*runner[G, S])(nil)
}

type runner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	p *Participant[G, S]
}

func NewRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, accessStructure accessstructures.Monotone, group algebra.PrimeGroup[G, S], prng io.Reader) (network.Runner[*mpc.BaseShard[G, S]], error) {
	p, err := NewParticipant(ctx, accessStructure, group, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}

	r := &runner[G, S]{
		p: p,
	}
	return r, nil
}

func (r *runner[G, S]) Run(rt *network.Router) (*mpc.BaseShard[G, S], error) {
	// r1
	r1bOut, err := r.p.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2bIn, err := exchange.BroadcastExchange(rt, r1CorrelationID, r.p.ctx.Quorum(), r1bOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}

	// r2
	r2bOut, r2uOut, err := r.p.Round2(r2bIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3bIn, r3uIn, err := exchange.Exchange(rt, r2CorrelationID, r.p.ctx.Quorum(), r2bOut, r2uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}

	// r3
	r3bOut, err := r.p.Round3(r3bIn, r3uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	r4bIn, err := exchange.BroadcastExchange(rt, r3CorrelationID, r.p.ctx.Quorum(), r3bOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 messages")
	}

	// r4
	shard, err := r.p.Round4(r4bIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	return shard, err
}
