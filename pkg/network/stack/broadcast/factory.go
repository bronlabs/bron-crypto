package broadcast

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/network/echo"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/auth"
)

var (
	_ ClientFactory = (*broadcastClientFactoryImpl)(nil)
)

type exchange struct {
	toFrom  types.IdentityKey
	payload []byte
}

type broadcastClientFactoryImpl struct {
	downstream auth.ClientFactory
}

func NewBroadcastClientFactory(downstream auth.ClientFactory) ClientFactory {
	return &broadcastClientFactoryImpl{downstream: downstream}
}

func (f *broadcastClientFactoryImpl) Dial(coordinatorURL string, sessionID []byte, identity types.AuthKey, protocol types.Protocol) Client {
	downstream := f.downstream.Dial(coordinatorURL, sessionID, identity, protocol.Participants().List())
	c := &broadcastClientImpl{
		id:                identity,
		downstream:        downstream,
		protocol:          protocol,
		senders:           make(map[messageId]*echo.Participant),
		responders:        make(map[messageId]*echo.Participant),
		messageBuffer:     make(map[messageId]network.RoundMessages[types.Protocol, *echo.Round2P2P]),
		outgoingBroadcast: make(chan *exchange, 1),
		incomingBroadcast: make(chan *exchange, 1),
		outgoingUnicast:   make(chan *exchange, 1),
		incomingUnicast:   make(chan *exchange, 1),
	}

	go c.processOutgoing()
	go c.processIncoming()
	return c
}
