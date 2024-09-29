package broadcast

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type ClientFactory interface {
	Dial(self types.AuthKey, protocol types.Protocol) Client
}

type MessageType string

const (
	P2P       MessageType = "p2p"
	BROADCAST MessageType = "broadcast"
)

type Client interface {
	SendTo(to types.IdentityKey, payload []byte)
	Broadcast(payload []byte)
	Recv() (from types.IdentityKey, typ MessageType, payload []byte)
	GetAuthKey() types.AuthKey
}
