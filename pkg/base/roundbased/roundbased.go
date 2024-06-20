package roundbased

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type UnicastExchanger[P any] interface {
	Send(source types.IdentityKey, messages ds.Map[types.IdentityKey, P])
	Receive(destination types.IdentityKey) ds.Map[types.IdentityKey, P]
}

type BroadcastExchanger[P any] interface {
	Send(me types.IdentityKey, message P)
	Receive(me types.IdentityKey) ds.Map[types.IdentityKey, P]
}

type MessageRouter interface {
	// RegisterBroadcastRound these any's should be whatever format we serialise into (not implemented yet, not needed for simulator)
	RegisterBroadcastRound(round int) BroadcastExchanger[any]
	RegisterUnicastRound(round int) UnicastExchanger[any]
}

type UnicastRound[U any] struct {
	o chan<- ds.Map[types.IdentityKey, U]
	i <-chan ds.Map[types.IdentityKey, U]
}

type BroadcastRound[B any] struct {
	o chan<- B
	i <-chan ds.Map[types.IdentityKey, B]
}

func NewUnicastRound[U any](me types.IdentityKey, round int, router MessageRouter) *UnicastRound[U] {
	exchange := router.RegisterUnicastRound(round)
	out := make(chan ds.Map[types.IdentityKey, U])
	in := make(chan ds.Map[types.IdentityKey, U])

	go func() {
		received := exchange.Receive(me)
		result := hashmap.NewHashableHashMap[types.IdentityKey, U]()
		for iter := received.Iterator(); iter.HasNext(); {
			e := iter.Next()
			party := e.Key
			payload, ok := e.Value.(U)
			if ok {
				result.Put(party, payload)
			}
		}
		in <- result
	}()
	go func() {
		result := <-out
		sent := hashmap.NewHashableHashMap[types.IdentityKey, any]()
		for iter := result.Iterator(); iter.HasNext(); {
			e := iter.Next()
			party := e.Key
			payload := e.Value
			sent.Put(party, payload)
		}
		exchange.Send(me, sent)
	}()

	return &UnicastRound[U]{
		o: out,
		i: in,
	}
}

func (u *UnicastRound[M]) UnicastOut() chan<- ds.Map[types.IdentityKey, M] {
	return u.o
}

func (u *UnicastRound[M]) UnicastIn() <-chan ds.Map[types.IdentityKey, M] {
	return u.i
}

func NewBroadcastRound[B any](me types.IdentityKey, round int, router MessageRouter) *BroadcastRound[B] {
	exchange := router.RegisterBroadcastRound(round)
	out := make(chan B)
	in := make(chan ds.Map[types.IdentityKey, B])

	go func() {
		received := exchange.Receive(me)
		result := hashmap.NewHashableHashMap[types.IdentityKey, B]()
		for iter := received.Iterator(); iter.HasNext(); {
			e := iter.Next()
			party := e.Key
			payload, ok := e.Value.(B)
			if ok {
				result.Put(party, payload)
			}
		}
		in <- result
	}()
	go func() {
		result := <-out
		exchange.Send(me, result)
	}()

	return &BroadcastRound[B]{
		o: out,
		i: in,
	}
}

func (b *BroadcastRound[M]) BroadcastOut() chan<- M {
	return b.o
}

func (b *BroadcastRound[M]) BroadcastIn() <-chan ds.Map[types.IdentityKey, M] {
	return b.i
}
