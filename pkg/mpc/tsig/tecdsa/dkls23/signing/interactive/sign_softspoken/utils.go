package sign_softspoken

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

type message[B network.Message, U network.Message] struct {
	broadcast B
	p2p       U
}

func validateIncomingMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], MB network.Message, MU network.Message](c *Cosigner[P, B, S], rIn network.Round, bIn network.RoundMessages[MB], uIn network.RoundMessages[MU]) (iter.Seq2[sharing.ID, message[MB, MU]], error) {
	if rIn != c.state.round {
		return nil, ErrFailed.WithMessage("invalid round")
	}

	return func(yield func(p sharing.ID, m message[MB, MU]) bool) {
		for id := range c.quorum.Iter() {
			if id == c.shard.Share().ID() {
				continue
			}

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

type messagePointerConstraint[MP network.Message, M any] interface {
	*M
	network.Message
}

func outgoingP2PMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], UPtr messagePointerConstraint[UPtr, U], U any](c *Cosigner[P, B, S], uOut ds.MutableMap[sharing.ID, UPtr]) iter.Seq2[sharing.ID, UPtr] {
	return func(yield func(p sharing.ID, out UPtr) bool) {
		for id := range c.quorum.Iter() {
			if id == c.shard.Share().ID() {
				continue
			}

			u := new(U)
			if !yield(id, UPtr(u)) {
				return
			}
			uOut.Put(id, UPtr(u))
		}
	}
}
