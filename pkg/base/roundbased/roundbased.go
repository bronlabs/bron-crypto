package roundbased

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type MessageRouter interface {
	RegisterBroadcastOutput(round int, me types.IdentityKey, bo <-chan any)
	RegisterBroadcastInput(round int, me types.IdentityKey, bi chan<- ds.Map[types.IdentityKey, any])

	RegisterUnicastOutput(round int, me types.IdentityKey, uo <-chan ds.Map[types.IdentityKey, any])
	RegisterUnicastInput(round int, me types.IdentityKey, ui chan<- ds.Map[types.IdentityKey, any])

	Done()
}

// Round
// normally I would just return a channel to write to but go won't allow casting channels
// maybe we can use https://pkg.go.dev/github.com/eapache/channels#Wrap to achieve that
type Round[OB, IB, OU, IU any] interface {
	SendBroadcast(message OB) error
	ReceiveBroadcast() (ds.Map[types.IdentityKey, IB], error)

	SendUnicast(message ds.Map[types.IdentityKey, OU]) error
	ReceiveUnicast() (ds.Map[types.IdentityKey, IU], error)
}
