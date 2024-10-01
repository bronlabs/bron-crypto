package round

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/broadcast"
	"sync"
)

var (
	_ ClientFactory = (*roundClientFactoryImpl)(nil)
)

type roundClientFactoryImpl struct {
	downstream broadcast.ClientFactory
}

func NewRoundClientFactory(downstream broadcast.ClientFactory) ClientFactory {
	return &roundClientFactoryImpl{downstream: downstream}
}

func (r *roundClientFactoryImpl) Dial(self types.AuthKey, protocol types.Protocol) Client {
	downstream := r.downstream.Dial(self, protocol)
	c := &roundClientImpl{
		downstream:      downstream,
		unicastBuffer:   make(map[string]ds.Map[types.IdentityKey, []byte]),
		broadcastBuffer: make(map[string]ds.Map[types.IdentityKey, []byte]),
		bufferLock:      sync.Mutex{},
	}
	c.bufferCondVar = sync.NewCond(&c.bufferLock)
	go c.processIncoming()

	return c
}
