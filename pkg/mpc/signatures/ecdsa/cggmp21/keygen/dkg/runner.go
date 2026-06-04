package dkg

import (
	"context"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/errs-go/errs"
)

const (
	// ProtocolName identifies this protocol in round-completion notifications.
	ProtocolName = "ECDSA_CGGMP21_DKG"

	r1CorrelationID = "BRON_CRYPTO_DKG_CGGMP21_R1"
	r2CorrelationID = "BRON_CRYPTO_DKG_CGGMP21_R2"
	r3CorrelationID = "BRON_CRYPTO_DKG_CGGMP21_R3"
)

func _[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]]() {
	var _ network.Runner[*cggmp21.Shard[P, B, S]] = (*runner[P, B, S])(nil)
}

type runner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	p *Participant[P, B, S]
}

// NewRunner wraps a Participant as a network.Runner that drives the four rounds
// over a router — broadcasting rounds 1 and 2 and unicasting the per-verifier
// round-3 proofs — and returns the resulting auxiliary-info shard. See
// NewParticipant for the argument requirements.
func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, baseShard *mpc.BaseShard[P, S], prng io.Reader) (network.Runner[*cggmp21.Shard[P, B, S]], error) {
	p, err := NewParticipant(ctx, baseShard, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}

	r := &runner[P, B, S]{
		p: p,
	}
	return r, nil
}

// Run executes the four rounds in order over the router, exchanging each round's
// messages and emitting a round-completion notification after each, and returns
// the final shard. Any round error is returned wrapped and aborts the run.
func (r *runner[P, B, S]) Run(ctx context.Context, rt *network.Router, callback network.NotificationCallback) (*cggmp21.Shard[P, B, S], error) {
	// r1
	r1bOut, err := r.p.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 1)

	// r2
	r2bIn, err := exchange.BroadcastExchange(ctx, rt, r1CorrelationID, r.p.ctx.Quorum(), r1bOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}
	r2bOut, err := r.p.Round2(r2bIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 2)

	// r3
	r3bIn, err := exchange.BroadcastExchange(ctx, rt, r2CorrelationID, r.p.ctx.Quorum(), r2bOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 broadcast messages")
	}
	r3uOut, err := r.p.Round3(r3bIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 3)

	// r4
	r4bIn, err := exchange.UnicastExchange(ctx, rt, r3CorrelationID, r3uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 unicast messages")
	}
	shard, err := r.p.Round4(r4bIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 4)
	return shard, nil
}
