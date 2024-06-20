package simulator

import (
	"sync"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	rb "github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type unicastExchanger[P any] struct {
	participants map[string]types.IdentityKey
	buffer       map[string][]*exchange[P]
	mutex        sync.Mutex
	cond         *sync.Cond
}

func NewUnicastExchanger[P any](participants ds.Set[types.IdentityKey]) rb.UnicastExchanger[P] {
	parties := make(map[string]types.IdentityKey)
	for iter := participants.Iterator(); iter.HasNext(); {
		p := iter.Next()
		parties[p.String()] = p
	}

	router := &unicastExchanger[P]{
		participants: parties,
		buffer:       make(map[string][]*exchange[P]),
		// mutex is stored here by value, so it is not accidentally copied
		mutex: sync.Mutex{},
	}
	router.cond = sync.NewCond(&router.mutex)

	return router
}

func (r *unicastExchanger[P]) Send(me types.IdentityKey, messages ds.Map[types.IdentityKey, P]) {
	r.cond.L.Lock()
	defer r.cond.L.Unlock()

	for iter := messages.Iterator(); iter.HasNext(); {
		e := iter.Next()
		destination := e.Key
		payload := e.Value
		if _, ok := r.buffer[destination.String()]; !ok {
			r.buffer[destination.String()] = []*exchange[P]{}
		}
		r.buffer[destination.String()] = append(r.buffer[destination.String()], &exchange[P]{
			from:    me.String(),
			payload: payload,
		})
	}
	r.cond.Broadcast()
}

func (r *unicastExchanger[P]) Receive(me types.IdentityKey) ds.Map[types.IdentityKey, P] {
	r.cond.L.Lock()
	defer r.cond.L.Unlock()
	for !r.hasAllMessages(me) {
		r.cond.Wait()
	}

	result := hashmap.NewHashableHashMap[types.IdentityKey, P]()
	for _, message := range r.buffer[me.String()] {
		result.Put(r.participants[message.from], message.payload)
	}

	return result
}

func (r *unicastExchanger[P]) hasAllMessages(me types.IdentityKey) bool {
main:
	for _, participant := range r.participants {
		if participant.Equal(me) {
			continue
		}

		for _, message := range r.buffer[me.String()] {
			if participant.String() == message.from {
				continue main
			}
		}
		return false
	}

	return true
}
