package rb

import "github.com/copperexchange/krypton-primitives/pkg/base/types"

type EchoBroadcast interface {
	Send(to types.IdentityKey, message []byte) error
	Receive() (from types.IdentityKey, message []byte, err error)

	Broadcast(message []byte) error
	ReceiveBroadcast() (from types.IdentityKey, message []byte, err error)
}
