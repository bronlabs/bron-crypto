package testutils

import (
	"encoding/hex"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/coordinator"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
)

var (
	_ coordinator.ClientFactory = (*SimulatorClientFactory)(nil)
	_ coordinator.Client        = (*SimulatorClient)(nil)
)

type message struct {
	from    string
	to      string
	payload []byte
}

type SimulatorClientFactory struct {
	incoming chan *message
	outgoing *sync.Map
}

func (f *SimulatorClientFactory) Dial(self types.IdentityKey) coordinator.Client {
	incoming := make(chan *message, 1)
	f.outgoing.Store(identityToString(self), incoming)

	c := &SimulatorClient{
		id:       self,
		incoming: incoming,
		outgoing: f.incoming,
	}

	return c
}

func (f *SimulatorClientFactory) process() {
	for {
		in := <-f.incoming
		from := in.from
		to := in.to
		payload := in.payload

		// do this asynchronously and with random delay to simulate network
		go func() {
			delay := rand.N[time.Duration](100) + 50
			time.Sleep(delay * time.Millisecond)

			outgoing, ok := f.outgoing.Load(to)
			if ok {
				outgoing.(chan *message) <- &message{
					from:    from,
					payload: payload,
				}
			}
		}()
	}
}

func NewSimulatorClientFactory() *SimulatorClientFactory {
	c := &SimulatorClientFactory{
		incoming: make(chan *message, 1),
		outgoing: new(sync.Map),
	}

	go c.process()
	return c
}

type SimulatorClient struct {
	id       types.IdentityKey
	incoming chan *message
	outgoing chan *message
}

func (c *SimulatorClient) SendTo(to types.IdentityKey, payload []byte) {
	c.outgoing <- &message{
		from:    identityToString(c.id),
		to:      identityToString(to),
		payload: payload,
	}
}

func (c *SimulatorClient) Recv() (from types.IdentityKey, payload []byte) {
	in := <-c.incoming
	return stringToIdentity(in.from), in.payload
}

func (c *SimulatorClient) GetIdentityKey() types.IdentityKey {
	return c.id
}

func identityToString(key types.IdentityKey) string {
	buf := key.PublicKey().ToAffineCompressed()
	return strings.ToUpper(hex.EncodeToString(buf))
}

func stringToIdentity(s string) types.IdentityKey {
	buf, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	pk, err := p256.NewCurve().Point().FromAffineCompressed(buf)
	if err != nil {
		panic(err)
	}
	return NewTestIdentityKey(pk)
}
