package roundbased

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"sync"
)

type SimulatorMessageRouter struct {
	lock                sync.Mutex
	participants        ds.Set[types.IdentityKey]
	unicastExchangers   map[int]*SimulatorUnicastExchanger[any]
	broadcastExchangers map[int]*SimulatorBroadcastExchanger[any]
}

func NewSimulatorMessageRouter(participants ds.Set[types.IdentityKey]) *SimulatorMessageRouter {
	router := &SimulatorMessageRouter{
		lock:                sync.Mutex{},
		participants:        participants,
		unicastExchangers:   make(map[int]*SimulatorUnicastExchanger[any]),
		broadcastExchangers: make(map[int]*SimulatorBroadcastExchanger[any]),
	}

	return router
}

func (r *SimulatorMessageRouter) RegisterBroadcastRound(round int) BroadcastExchanger[any] {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.broadcastExchangers[round]; !ok {
		r.broadcastExchangers[round] = NewSimulatorBroadcastExchanger[any](r.participants)
	}
	return r.broadcastExchangers[round]
}

func (r *SimulatorMessageRouter) RegisterUnicastRound(round int) UnicastExchanger[any] {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.unicastExchangers[round]; !ok {
		r.unicastExchangers[round] = NewSimulatorUnicastExchanger[any](r.participants)
	}
	return r.unicastExchangers[round]
}
