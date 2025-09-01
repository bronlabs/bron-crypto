package dkg

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type message[B network.Message, U network.Message] struct {
	broadcast B
	p2p       U
}

func incomingMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], MB network.Message, MU network.Message](p *Participant[P, B, S], rIn network.Round, bIn network.RoundMessages[MB], uIn network.RoundMessages[MU]) iter.Seq2[sharing.ID, message[MB, MU]] {
	return func(yield func(p sharing.ID, m message[MB, MU]) bool) {
		for id := range p.ac.Shareholders().Iter() {
			if id == p.sharingId {
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
	}
}

func incomingP2PMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], MU network.Message](p *Participant[P, B, S], rIn network.Round, uIn network.RoundMessages[MU]) iter.Seq2[sharing.ID, MU] {
	return func(yield func(p sharing.ID, m MU) bool) {
		for id := range p.ac.Shareholders().Iter() {
			if id == p.sharingId {
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
	}
}

type messagePointerConstraint[MP network.Message, M any] interface {
	*M
	network.Message
}

func outgoingP2PMessages[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], UPtr messagePointerConstraint[UPtr, U], U any](p *Participant[P, B, S], uOut ds.MutableMap[sharing.ID, UPtr]) iter.Seq2[sharing.ID, UPtr] {
	return func(yield func(p sharing.ID, out UPtr) bool) {
		for id := range p.ac.Shareholders().Iter() {
			if id == p.sharingId {
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
