package testutils

import (
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/stretchr/testify/require"
	"reflect"
)

// MapO2I maps the outputs of all participants in a round of a protocol to the inputs of the next round
// with serializing and deserializing them throughout the process.
func MapO2I[
	ProtocolT types.Protocol, PartyT types.Participant, BcastT network.Message[ProtocolT], UnicastT network.Message[ProtocolT],
](
	t require.TestingT,
	participants []PartyT,
	broadcastOutputs []BcastT,
	UnicastOutputs []network.RoundMessages[ProtocolT, UnicastT],
) (
	broadcastInputs []network.RoundMessages[ProtocolT, BcastT],
	UnicastInputs []network.RoundMessages[ProtocolT, UnicastT],
) {
	if len(broadcastOutputs) != 0 {
		broadcastInputs = MapBroadcastO2I(t, participants, broadcastOutputs)
	}
	if len(UnicastOutputs) != 0 {
		UnicastInputs = MapUnicastO2I(t, participants, UnicastOutputs)
	}
	return broadcastInputs, UnicastInputs
}

// MapBroadcastO2I maps the broadcasts of all participants in a round of a protocol to the inputs of the next round
// with serializing and deserializing them throughout the process.
func MapBroadcastO2I[
	ProtocolT types.Protocol, PartyT types.Participant, BcastT network.Message[ProtocolT],
](
	t require.TestingT,
	participants []PartyT,
	broadcastOutputs []BcastT,
) (
	broadcastInputs []network.RoundMessages[ProtocolT, BcastT],
) {
	broadcastInputs = make([]network.RoundMessages[ProtocolT, BcastT], len(participants))
	for receiver := range participants {
		broadcastInputs[receiver] = network.NewRoundMessages[ProtocolT, BcastT]()
		for sender := range participants {
			if sender == receiver {
				continue
			}
			msg := broadcastOutputs[sender]
			broadcastInputs[receiver].Put(participants[sender].IdentityKey(), GobRoundTripMessage(t, msg))
		}
	}
	return broadcastInputs
}

// MapUnicastO2I maps the P2P messages of all participants in a round of a protocol to the inputs of the next round
// with serializing and deserializing them throughout the process.
func MapUnicastO2I[
	ProtocolT types.Protocol, PartyT types.Participant, UnicastT network.Message[ProtocolT],
](
	t require.TestingT,
	participants []PartyT,
	p2pOutputs []network.RoundMessages[ProtocolT, UnicastT],
) (
	p2pInputs []network.RoundMessages[ProtocolT, UnicastT],
) {
	p2pInputs = make([]network.RoundMessages[ProtocolT, UnicastT], len(participants))
	for receiver := range participants {
		p2pInputs[receiver] = network.NewRoundMessages[ProtocolT, UnicastT]()
		for sender := range participants {
			if sender == receiver || p2pOutputs[sender] == nil {
				continue
			}
			msg, exists := p2pOutputs[sender].Get(participants[receiver].IdentityKey())
			if !exists {
				continue
			}
			p2pInputs[receiver].Put(participants[sender].IdentityKey(), GobRoundTripMessage(t, msg))
		}
	}
	return p2pInputs
}

func GobRoundTripMessage[P types.Protocol, M network.Message[P]](t require.TestingT, message M) M {
	if reflect.ValueOf(message).IsNil() {
		return message
	}

	return GobRoundTrip(t, message)
}
