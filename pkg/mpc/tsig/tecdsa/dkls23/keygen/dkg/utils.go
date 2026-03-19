package dkg

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

func incomingP2PMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], MU network.Message[*Participant[P, B, S]]](p *Participant[P, B, S], rIn network.Round, uIn network.RoundMessages[MU, *Participant[P, B, S]]) (iter.Seq2[sharing.ID, MU], error) {
	if rIn != p.round {
		return nil, ErrRound.WithMessage("invalid round")
	}

	return func(yield func(p sharing.ID, m MU) bool) {
		for id := range p.baseShard.AccessStructure().Shareholders().Iter() {
			if id == p.baseShard.Share().ID() {
				continue
			}

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

type messagePointerConstraint[MP network.Message[*Participant[P, B, S]], P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], M any] interface {
	network.Message[*Participant[P, B, S]]
	*M
}

func outgoingP2PMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], UPtr messagePointerConstraint[UPtr, P, B, S, U], U any](p *Participant[P, B, S], uOut ds.MutableMap[sharing.ID, UPtr]) iter.Seq2[sharing.ID, UPtr] {
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
