package roundbased

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"sync"
)

type SimulatorBroadcastExchanger[P any] struct {
	participants map[string]types.IdentityKey
	buffer       []*SimulatorExchange[P]
	mutex        sync.Mutex
	cond         *sync.Cond
}

func NewSimulatorBroadcastExchanger[P any](participants ds.Set[types.IdentityKey]) *SimulatorBroadcastExchanger[P] {
	parties := make(map[string]types.IdentityKey)
	for iter := participants.Iterator(); iter.HasNext(); {
		p := iter.Next()
		parties[p.String()] = p
	}

	exchanger := &SimulatorBroadcastExchanger[P]{
		participants: parties,
		buffer:       make([]*SimulatorExchange[P], 0),
		mutex:        sync.Mutex{},
	}
	exchanger.cond = sync.NewCond(&exchanger.mutex)

	return exchanger
}

func (r *SimulatorBroadcastExchanger[P]) Send(me types.IdentityKey, message P) {
	r.cond.L.Lock()
	defer r.cond.L.Unlock()

	r.buffer = append(r.buffer, &SimulatorExchange[P]{
		from:    me.String(),
		payload: message,
	})
	r.cond.Broadcast()
}

func (r *SimulatorBroadcastExchanger[P]) Receive(me types.IdentityKey) ds.Map[types.IdentityKey, P] {
	r.cond.L.Lock()
	defer r.cond.L.Unlock()
	for !r.hasAllMessages(me) {
		r.cond.Wait()
	}

	result := hashmap.NewHashableHashMap[types.IdentityKey, P]()
	for _, message := range r.buffer {
		if message.from == me.String() {
			continue
		}
		result.Put(r.participants[message.from], message.payload)
	}

	return result
}

func (r *SimulatorBroadcastExchanger[P]) hasAllMessages(me types.IdentityKey) bool {
main:
	for _, participant := range r.participants {
		if participant.Equal(me) {
			continue
		}

		for _, message := range r.buffer {
			if participant.String() == message.from {
				continue main
			}
		}
		return false
	}

	return true
}
