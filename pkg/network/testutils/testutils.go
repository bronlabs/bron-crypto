package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type TestParticipant interface {
	SharingID() sharing.ID
}

// MapO2I maps the outputs of all participants in a round of a protocol to the inputs of the next round
// with serialising and deserializing them throughout the process.
func MapO2I[
	P TestParticipant, BcastT, UnicastT network.Message,
](
	tb testing.TB,
	participants []P,
	broadcastOutputs map[sharing.ID]BcastT,
	UnicastOutputs map[sharing.ID]network.RoundMessages[UnicastT],
) (
	broadcastInputs map[sharing.ID]network.RoundMessages[BcastT],
	UnicastInputs map[sharing.ID]network.RoundMessages[UnicastT],
) {
	tb.Helper()
	if len(broadcastOutputs) != 0 {
		broadcastInputs = MapBroadcastO2I(tb, participants, broadcastOutputs)
	}
	if len(UnicastOutputs) != 0 {
		UnicastInputs = MapUnicastO2I(tb, participants, UnicastOutputs)
	}
	return broadcastInputs, UnicastInputs
}

// MapBroadcastO2I maps the broadcasts of all participants in a round of a protocol to the inputs of the next round
// with serialising and deserializing them throughout the process.
func MapBroadcastO2I[
	P interface {
		SharingID() sharing.ID
	}, BcastT network.Message,
](
	tb testing.TB,
	participants []P,
	broadcastOutputs map[sharing.ID]BcastT,
) (
	broadcastInputs map[sharing.ID]network.RoundMessages[BcastT],
) {
	tb.Helper()
	broadcastInputs = make(map[sharing.ID]network.RoundMessages[BcastT], len(participants))
	for _, receiver := range participants {
		inputs := hashmap.NewComparable[sharing.ID, BcastT]()
		for _, sender := range participants {
			if sender.SharingID() == receiver.SharingID() {
				continue
			}
			msg, ok := broadcastOutputs[sender.SharingID()]
			if ok {
				inputs.Put(sender.SharingID(), CBORRoundTrip(tb, msg))
			}
		}
		broadcastInputs[receiver.SharingID()] = inputs.Freeze()
	}
	return broadcastInputs
}

// MapUnicastO2I maps the P2P messages of all participants in a round of a protocol to the inputs of the next round
// with serialising and deserializing them throughout the process.
func MapUnicastO2I[
	P interface {
		SharingID() sharing.ID
	}, UnicastT network.Message,
](
	tb testing.TB,
	participants []P,
	p2pOutputs map[sharing.ID]network.RoundMessages[UnicastT],
) (
	p2pInputs map[sharing.ID]network.RoundMessages[UnicastT],
) {
	tb.Helper()
	p2pInputs = make(map[sharing.ID]network.RoundMessages[UnicastT], len(participants))
	for _, receiver := range participants {
		inputs := hashmap.NewComparable[sharing.ID, UnicastT]()
		for _, sender := range participants {
			if sender.SharingID() == receiver.SharingID() {
				continue
			}
			p2pOutput, ok := p2pOutputs[sender.SharingID()]
			if ok {
				msg, exists := p2pOutput.Get(receiver.SharingID())
				if exists {
					inputs.Put(sender.SharingID(), CBORRoundTrip(tb, msg))
				}
			}
		}
		p2pInputs[receiver.SharingID()] = inputs.Freeze()

	}
	return p2pInputs
}
