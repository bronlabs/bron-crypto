package testutils

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/auth"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/broadcast"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/round"
)

type simulatorStack struct {
	factory round.ClientFactory
}

type simulatorClient struct {
	client round.Client
}

func (s *simulatorClient) RoundSend(roundId string, broadcastMessage []byte, unicastMessages ds.Map[types.IdentityKey, []byte]) {
	s.client.Send(roundId, broadcastMessage, unicastMessages)
}

func (s *simulatorClient) RoundReceive(roundId string, broadcastFrom ds.Set[types.IdentityKey], unicastFrom ds.Set[types.IdentityKey]) (b ds.Map[types.IdentityKey, []byte], u ds.Map[types.IdentityKey, []byte]) {
	var bList []types.IdentityKey
	if broadcastFrom != nil {
		bList = broadcastFrom.List()
	}

	var uList []types.IdentityKey
	if unicastFrom != nil {
		uList = unicastFrom.List()
	}

	return s.client.Receive(roundId, bList, uList)
}

func NewSimulatorStack() stack.Stack {
	s := &simulatorStack{
		factory: round.NewRoundClientFactory(broadcast.NewBroadcastClientFactory(auth.NewAuthClientFactory(NewSimulatorClientFactory()))),
	}

	return s
}

func (s *simulatorStack) Dial(id types.AuthKey, protocol types.Protocol) stack.ProtocolClient {
	c := s.factory.Dial(id, protocol)
	return &simulatorClient{c}
}
