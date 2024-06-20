package simulator

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	rb "github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type echoBroadcastMessage[P comparable] struct {
	echo ds.Map[types.IdentityKey, P]
}

type echoBroadcastExchanger[P comparable] struct {
	participants ds.Set[types.IdentityKey]
	r1Exchanger  rb.UnicastExchanger[P]
	r2Exchanger  rb.UnicastExchanger[*echoBroadcastMessage[P]]
}

func NewEchoBroadcastExchanger[P comparable](participants ds.Set[types.IdentityKey]) rb.BroadcastExchanger[P] {
	return &echoBroadcastExchanger[P]{
		participants: participants,
		r1Exchanger:  NewUnicastExchanger[P](participants),
		r2Exchanger:  NewUnicastExchanger[*echoBroadcastMessage[P]](participants),
	}
}

func (eb *echoBroadcastExchanger[P]) Send(me types.IdentityKey, message P) {
	outgoing := hashmap.NewHashableHashMap[types.IdentityKey, P]()
	for iter := eb.participants.Iterator(); iter.HasNext(); {
		p := iter.Next()
		if p.Equal(me) {
			continue
		}
		outgoing.Put(p, message)
	}
	eb.r1Exchanger.Send(me, outgoing)
}

func (eb *echoBroadcastExchanger[P]) Receive(me types.IdentityKey) ds.Map[types.IdentityKey, P] {
	received := eb.r1Exchanger.Receive(me)

	// echo whatever you received
	echo := hashmap.NewHashableHashMap[types.IdentityKey, *echoBroadcastMessage[P]]()
	for iter := eb.participants.Iterator(); iter.HasNext(); {
		p := iter.Next()
		if p.Equal(me) {
			continue
		}
		echo.Put(p, &echoBroadcastMessage[P]{
			echo: received,
		})
	}
	eb.r2Exchanger.Send(me, echo)

	echoReceived := eb.r2Exchanger.Receive(me)
	result := hashmap.NewHashableHashMap[types.IdentityKey, P]()
	for i1 := echoReceived.Iterator(); i1.HasNext(); {
		e1 := i1.Next()
		for i2 := e1.Value.echo.Iterator(); i2.HasNext(); {
			e2 := i2.Next()
			sender := e2.Key
			message := e2.Value
			if !sender.Equal(me) {
				existing, exists := result.Get(sender)
				if !exists {
					result.Put(sender, message)
				} else if existing != message {
					// TODO:
					// here we should compare messages, but since the serialisation is not yet implemented
					// we just compare pointers above, and it should work because simulator just passes mostly pointers for now.
					panic("someone is cheating")
				}
			}
		}
	}

	return result
}
