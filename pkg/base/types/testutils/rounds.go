package testutils

import (
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"testing"
)

// MapO2I maps the outputs of all participants in a round of a protocol to the inputs of the next round
// with serializing and deserializing them throughout the process.
func MapO2I[P types.Participant, B, U any](
	tb testing.TB,
	participants []P,
	broadcastOutputs []B,
	unicastOutputs []network.RoundMessages[U],
) (
	broadcastInputs []network.RoundMessages[B],
	UnicastInputs []network.RoundMessages[U],
) {
	if len(broadcastOutputs) != 0 {
		broadcastInputs = MapBroadcastO2I(tb, participants, broadcastOutputs)
	}
	if len(unicastOutputs) != 0 {
		UnicastInputs = MapUnicastO2I(tb, participants, unicastOutputs)
	}
	return broadcastInputs, UnicastInputs
}

// MapBroadcastO2I maps the broadcasts of all participants in a round of a protocol to the inputs of the next round
// with serializing and deserializing them throughout the process.
func MapBroadcastO2I[P types.Participant, B any](
	tb testing.TB,
	participants []P,
	broadcastOutputs []B,
) (
	broadcastInputs []network.RoundMessages[B],
) {
	broadcastInputs = make([]network.RoundMessages[B], len(participants))
	for receiver := range participants {
		broadcastInputs[receiver] = network.NewRoundMessages[B]()
		for sender := range participants {
			if sender == receiver {
				continue
			}
			msg := broadcastOutputs[sender]
			broadcastInputs[receiver].Put(participants[sender].IdentityKey(), GobRoundTrip(tb, msg))
		}
	}
	return broadcastInputs
}

// MapUnicastO2I maps the P2P messages of all participants in a round of a protocol to the inputs of the next round
// with serializing and deserializing them throughout the process.
func MapUnicastO2I[P types.Participant, U any,
](
	tb testing.TB,
	participants []P,
	p2pOutputs []network.RoundMessages[U],
) (
	p2pInputs []network.RoundMessages[U],
) {
	p2pInputs = make([]network.RoundMessages[U], len(participants))
	for receiver := range participants {
		p2pInputs[receiver] = network.NewRoundMessages[U]()
		for sender := range participants {
			if sender == receiver || p2pOutputs[sender] == nil {
				continue
			}
			msg, exists := p2pOutputs[sender].Get(participants[receiver].IdentityKey())
			if !exists {
				continue
			}
			p2pInputs[receiver].Put(participants[sender].IdentityKey(), GobRoundTrip(tb, msg)) // TODO: add gob roundtrip
		}
	}
	return p2pInputs
}
