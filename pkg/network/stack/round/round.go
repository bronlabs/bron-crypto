package round

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

type ClientFactory interface {
	Dial(self types.AuthKey, protocol types.Protocol) Client
}

type Client interface {
	RegisterRound(roundId string)
	RegisterBroadcastRound(roundId string)
	RegisterUnicastRound(roundId string)
	GetAuthKey() types.AuthKey
}

type RoundBase interface {
	GetId() string
}

type BroadcastRound interface {
	RoundBase
	Broadcast(message network.Message[])
}

type UnicastRound interface {
	RoundBase
}
