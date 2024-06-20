package simulator

import (
	"sync"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	rb "github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type broadcastExchanger[P any] struct {
	participants map[string]types.IdentityKey
	buffer       []*exchange[P]
	mutex        sync.Mutex
	cond         *sync.Cond
}

func NewBroadcastExchanger[P any](participants ds.Set[types.IdentityKey]) rb.BroadcastExchanger[P] {
	parties := make(map[string]types.IdentityKey)
	for iter := participants.Iterator(); iter.HasNext(); {
		p := iter.Next()
		parties[p.String()] = p
	}

	exchanger := &broadcastExchanger[P]{
		participants: parties,
		buffer:       []*exchange[P]{},
		// mutex is stored here by value, so it is not accidentally copied
		mutex: sync.Mutex{},
	}
	exchanger.cond = sync.NewCond(&exchanger.mutex)

	return exchanger
}

func (r *broadcastExchanger[P]) Send(me types.IdentityKey, message P) {
	r.cond.L.Lock()
	defer r.cond.L.Unlock()

	r.buffer = append(r.buffer, &exchange[P]{
		from:    me.String(),
		payload: message,
	})
	r.cond.Broadcast()
}

func (r *broadcastExchanger[P]) Receive(me types.IdentityKey) ds.Map[types.IdentityKey, P] {
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

func (r *broadcastExchanger[P]) hasAllMessages(me types.IdentityKey) bool {
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
