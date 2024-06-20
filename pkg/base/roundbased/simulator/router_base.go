package simulator

import (
	"sync"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	rb "github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var (
	_ rb.MessageRouter = (*routerBase)(nil)
)

type routerBase struct {
	uxFactory func(participants ds.Set[types.IdentityKey]) rb.UnicastExchanger[any]
	bxFactory func(participants ds.Set[types.IdentityKey]) rb.BroadcastExchanger[any]

	lock                sync.Mutex
	participants        ds.Set[types.IdentityKey]
	unicastExchangers   map[int]rb.UnicastExchanger[any]
	broadcastExchangers map[int]rb.BroadcastExchanger[any]
}

func newRouterBase(
	participants ds.Set[types.IdentityKey],
	uxFactory func(participants ds.Set[types.IdentityKey]) rb.UnicastExchanger[any],
	bxFactory func(participants ds.Set[types.IdentityKey]) rb.BroadcastExchanger[any],
) *routerBase {
	router := &routerBase{
		uxFactory:           uxFactory,
		bxFactory:           bxFactory,
		lock:                sync.Mutex{},
		participants:        participants,
		unicastExchangers:   make(map[int]rb.UnicastExchanger[any]),
		broadcastExchangers: make(map[int]rb.BroadcastExchanger[any]),
	}

	return router
}

func (r *routerBase) RegisterBroadcastRound(round int) rb.BroadcastExchanger[any] {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.broadcastExchangers[round]; !ok {
		r.broadcastExchangers[round] = r.bxFactory(r.participants)
	}
	return r.broadcastExchangers[round]
}

func (r *routerBase) RegisterUnicastRound(round int) rb.UnicastExchanger[any] {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.unicastExchangers[round]; !ok {
		r.unicastExchangers[round] = r.uxFactory(r.participants)
	}
	return r.unicastExchangers[round]
}
