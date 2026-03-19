package sign

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

type message[B any, U any] struct {
	broadcast B
	p2p       U
}

func validateIncomingMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], MB network.Message[*Cosigner[P, B, S]], MU network.Message[*Cosigner[P, B, S]]](c *Cosigner[P, B, S], rIn network.Round, bIn network.RoundMessages[MB, *Cosigner[P, B, S]], uIn network.RoundMessages[MU, *Cosigner[P, B, S]]) (iter.Seq2[sharing.ID, message[MB, MU]], error) {
	if rIn != c.state.round {
		return nil, ErrFailed.WithMessage("invalid round")
	}

	return func(yield func(p sharing.ID, m message[MB, MU]) bool) {
		for id := range c.ctx.OtherPartiesOrdered() {
			b, ok := bIn.Get(id)
			if !ok {
				panic("this should never happen: missing broadcast message")
			}
			u, ok := uIn.Get(id)
			if !ok {
				panic("this should never happen: missing unicast message")
			}
			if !yield(id, message[MB, MU]{broadcast: b, p2p: u}) {
				return
			}
		}
	}, nil
}

func validateIncomingP2PMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], MU network.Message[*Cosigner[P, B, S]]](c *Cosigner[P, B, S], rIn network.Round, uIn network.RoundMessages[MU, *Cosigner[P, B, S]]) (iter.Seq2[sharing.ID, MU], error) {
	if rIn != c.state.round {
		return nil, ErrFailed.WithMessage("invalid round")
	}

	return func(yield func(p sharing.ID, m MU) bool) {
		for id := range c.ctx.OtherPartiesOrdered() {
			u, ok := uIn.Get(id)
			if !ok {
				panic("this should never happen: missing unicast message")
			}
			if !yield(id, u) {
				return
			}
		}
	}, nil
}

type messagePointerConstraint[MP network.Message[*Cosigner[P, B, S]], P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], M any] interface {
	network.Message[*Cosigner[P, B, S]]
	*M
}

func outgoingP2PMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], UPtr messagePointerConstraint[UPtr, P, B, S, U], U any](p *Cosigner[P, B, S], uOut ds.MutableMap[sharing.ID, UPtr]) iter.Seq2[sharing.ID, UPtr] {
	return func(yield func(p sharing.ID, out UPtr) bool) {
		for id := range p.ctx.OtherPartiesOrdered() {
			u := new(U)
			if !yield(id, UPtr(u)) {
				return
			}
			uOut.Put(id, UPtr(u))
		}
	}
}
