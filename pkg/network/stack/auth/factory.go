package auth

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/coordinator"
)

var (
	_ ClientFactory = (*authClientFactoryImpl)(nil)
)

type exchange struct {
	toFrom  types.IdentityKey
	payload []byte
}

type authClientFactoryImpl struct {
	downstream coordinator.ClientFactory
}

func NewAuthClientFactory(downstream coordinator.ClientFactory) ClientFactory {
	return &authClientFactoryImpl{
		downstream: downstream,
	}
}

func (f *authClientFactoryImpl) Dial(coordinatorURL string, sessionID []byte, identity types.AuthKey, participants []types.IdentityKey) Client {
	downstream := f.downstream.Dial(coordinatorURL, sessionID, identity, participants)
	c := &authClientImpl{
		id:         identity,
		downstream: downstream,
		outgoing:   make(chan *exchange, 1),
		incoming:   make(chan *exchange, 1),
	}

	go c.processOutgoing()
	go c.processIncoming()
	return c
}
