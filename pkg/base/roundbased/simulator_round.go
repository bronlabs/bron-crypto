package roundbased

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var (
	_ Round[any, any, any, any] = (*simulatorRound[any, any, any, any])(nil)
)

type simulatorRound[OB, IB, OU, IU any] struct {
	bo chan<- any
	bi <-chan ds.Map[types.IdentityKey, any]
	uo chan<- ds.Map[types.IdentityKey, any]
	ui <-chan ds.Map[types.IdentityKey, any]
}

// NewSimulatorRound
// This should be proper Round when serialization of all messages is implemented
func NewSimulatorRound[OB, IB, OU, IU any](router MessageRouter, round int, me types.IdentityKey) Round[OB, IB, OU, IU] {
	bo := make(chan any)
	bi := make(chan ds.Map[types.IdentityKey, any])
	uo := make(chan ds.Map[types.IdentityKey, any])
	ui := make(chan ds.Map[types.IdentityKey, any])

	router.RegisterBroadcastOutput(round, me, bo)
	router.RegisterBroadcastInput(round, me, bi)
	router.RegisterUnicastOutput(round, me, uo)
	router.RegisterUnicastInput(round, me, ui)

	return &simulatorRound[OB, IB, OU, IU]{
		bo,
		bi,
		uo,
		ui,
	}
}

func (r *simulatorRound[OB, _, _, _]) SendBroadcast(message OB) error {
	r.bo <- message
	return nil
}

func (r *simulatorRound[_, _, OU, _]) SendUnicast(message ds.Map[types.IdentityKey, OU]) error {
	erased := hashmap.NewHashableHashMap[types.IdentityKey, any]()
	for iter := message.Iterator(); iter.HasNext(); {
		entry := iter.Next()
		erased.Put(entry.Key, entry.Value)
	}
	r.uo <- erased
	return nil
}

func (r *simulatorRound[_, IB, _, _]) ReceiveBroadcast() (ds.Map[types.IdentityKey, IB], error) {
	input := <-r.bi

	result := hashmap.NewHashableHashMap[types.IdentityKey, IB]()
	for iter := input.Iterator(); iter.HasNext(); {
		entry := iter.Next()
		key := entry.Key
		value, ok := entry.Value.(IB)
		if !ok {
			return nil, errs.NewSerialisation("invalid message type received")
		}
		result.Put(key, value)
	}

	return result, nil
}

func (r *simulatorRound[_, _, _, IU]) ReceiveUnicast() (ds.Map[types.IdentityKey, IU], error) {
	input := <-r.ui

	result := hashmap.NewHashableHashMap[types.IdentityKey, IU]()
	for iter := input.Iterator(); iter.HasNext(); {
		entry := iter.Next()
		key := entry.Key
		value, ok := entry.Value.(IU)
		if !ok {
			return nil, errs.NewSerialisation("invalid message type received")
		}
		result.Put(key, value)
	}

	return result, nil
}
