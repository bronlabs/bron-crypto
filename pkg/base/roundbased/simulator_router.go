package roundbased

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"sync"
	"sync/atomic"
)

var (
	_ MessageRouter = (*simulatorMessageRouter)(nil)
)

type simulatorMessage struct {
	from    types.IdentityKey
	payload any // TODO: this should be []byte but currently messages are NOT serializable
}

type simulatorMessageRouter struct {
	participants ds.Set[types.IdentityKey]
	done         atomic.Bool

	broadcastBuffer                 map[int][]*simulatorMessage
	broadcastBufferLock             sync.Mutex
	broadcastBufferChangedCondition *sync.Cond

	unicastBuffer                 map[int]ds.Map[types.IdentityKey, []*simulatorMessage]
	unicastBufferLock             sync.Mutex
	unicastBufferChangedCondition *sync.Cond
}

func NewSimulatorMessageRouter(participants ds.Set[types.IdentityKey]) MessageRouter {
	router := &simulatorMessageRouter{
		participants:        participants,
		broadcastBuffer:     make(map[int][]*simulatorMessage),
		broadcastBufferLock: sync.Mutex{},
		unicastBuffer:       make(map[int]ds.Map[types.IdentityKey, []*simulatorMessage]),
		unicastBufferLock:   sync.Mutex{},
	}
	router.broadcastBufferChangedCondition = sync.NewCond(&router.broadcastBufferLock)
	router.unicastBufferChangedCondition = sync.NewCond(&router.unicastBufferLock)

	return router
}

func (r *simulatorMessageRouter) RegisterBroadcastOutput(round int, me types.IdentityKey, bo <-chan any) {
	go func() {
		for !r.done.Load() {
			select {
			case m, ok := <-bo:
				if !ok {
					break
				}

				message := &simulatorMessage{
					from:    me,
					payload: m,
				}

				r.broadcastBufferChangedCondition.L.Lock()
				_, ok = r.broadcastBuffer[round+1]
				if !ok {
					r.broadcastBuffer[round+1] = make([]*simulatorMessage, 0)
				}
				r.broadcastBuffer[round+1] = append(r.broadcastBuffer[round+1], message)
				r.broadcastBufferChangedCondition.Broadcast()
				r.broadcastBufferChangedCondition.L.Unlock()
			}
		}
	}()
}

func (r *simulatorMessageRouter) RegisterUnicastOutput(round int, me types.IdentityKey, uo <-chan ds.Map[types.IdentityKey, any]) {
	go func() {
		for !r.done.Load() {
			select {
			case m, ok := <-uo:
				if !ok {
					break
				}

				r.unicastBufferChangedCondition.L.Lock()
				_, ok = r.unicastBuffer[round+1]
				if !ok {
					r.unicastBuffer[round+1] = hashmap.NewHashableHashMap[types.IdentityKey, []*simulatorMessage]()
				}
				for iter := m.Iterator(); iter.HasNext(); {
					entry := iter.Next()
					to := entry.Key
					msg := entry.Value
					old, exists := r.unicastBuffer[round+1].Get(me)
					if !exists {
						r.unicastBuffer[round+1].Put(to, []*simulatorMessage{{
							from:    me,
							payload: msg,
						}})
					} else {
						r.unicastBuffer[round+1].Put(to, append(old, &simulatorMessage{
							from:    me,
							payload: msg,
						}))
					}
				}
				r.unicastBufferChangedCondition.L.Unlock()
			}
		}
	}()
}

func (r *simulatorMessageRouter) RegisterBroadcastInput(round int, me types.IdentityKey, bi chan<- ds.Map[types.IdentityKey, any]) {
	go func() {
		for !r.done.Load() {
			r.broadcastBufferChangedCondition.L.Lock()
			// wait for all the messages
			if !r.haveAllMessages(r.broadcastBuffer[round], me) {
				r.broadcastBufferChangedCondition.Wait()
				r.broadcastBufferChangedCondition.L.Unlock()
				continue
			}

			// extract messages
			input := hashmap.NewHashableHashMap[types.IdentityKey, any]()
			for _, m := range r.broadcastBuffer[round] {
				input.Put(m.from, m.payload)
			}
			r.broadcastBufferChangedCondition.L.Unlock()

			bi <- input
		}
	}()
}

func (r *simulatorMessageRouter) RegisterUnicastInput(round int, me types.IdentityKey, ui chan<- ds.Map[types.IdentityKey, any]) {
	go func() {
		for !r.done.Load() {
			r.unicastBufferChangedCondition.L.Lock()

			// wait for all messages
			if r.unicastBuffer[round] == nil {
				r.unicastBufferChangedCondition.Wait()
				r.unicastBufferChangedCondition.L.Unlock()
				continue
			}
			input, exists := r.unicastBuffer[round].Get(me)
			if !exists || !r.haveAllMessages(input, me) {
				r.unicastBufferChangedCondition.Wait()
				r.unicastBufferChangedCondition.L.Unlock()
				continue
			}

			// extract messages
			result := hashmap.NewHashableHashMap[types.IdentityKey, any]()
			for _, m := range input {
				result.Put(m.from, m.payload)
			}
			r.unicastBufferChangedCondition.L.Unlock()

			ui <- result
		}
	}()
}

func (r *simulatorMessageRouter) haveAllMessages(messages []*simulatorMessage, me types.IdentityKey) bool {
	for iter := r.participants.Iterator(); iter.HasNext(); {
		id := iter.Next()
		if id.Equal(me) {
			continue
		}

		if !r.containsMessageFrom(messages, id) {
			return false
		}
	}

	return true
}

func (r *simulatorMessageRouter) containsMessageFrom(messages []*simulatorMessage, from types.IdentityKey) bool {
	for _, message := range messages {
		if message.from.Equal(from) {
			return true
		}
	}

	return false
}

func (r *simulatorMessageRouter) Done() {
	r.done.CompareAndSwap(false, true)
	r.broadcastBufferChangedCondition.Broadcast()
	r.unicastBufferChangedCondition.Broadcast()
}
