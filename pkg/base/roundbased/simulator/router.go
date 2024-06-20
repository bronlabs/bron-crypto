package simulator

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	rb "github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

func NewSimpleMessageRouter(participants ds.Set[types.IdentityKey]) rb.MessageRouter {
	return newRouterBase(participants, NewUnicastExchanger[any], NewBroadcastExchanger[any])
}

func NewEchoBroadcastMessageRouter(participants ds.Set[types.IdentityKey]) rb.MessageRouter {
	return newRouterBase(participants, NewUnicastExchanger[any], NewEchoBroadcastExchanger[any])
}
