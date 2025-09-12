package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/stretchr/testify/require"
)

// MapO2I maps the outputs of all participants in a round of a protocol to the inputs of the next round
// with serializing and deserializing them throughout the process.
func MapO2I[
	P interface {
		SharingID() sharing.ID
	}, BcastT, UnicastT network.Message,
](
	t testing.TB,
	participants []P,
	broadcastOutputs map[sharing.ID]BcastT,
	UnicastOutputs map[sharing.ID]network.RoundMessages[UnicastT],
) (
	broadcastInputs map[sharing.ID]network.RoundMessages[BcastT],
	UnicastInputs map[sharing.ID]network.RoundMessages[UnicastT],
) {
	t.Helper()
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
	P interface {
		SharingID() sharing.ID
	}, BcastT network.Message,
](
	t testing.TB,
	participants []P,
	broadcastOutputs map[sharing.ID]BcastT,
) (
	broadcastInputs map[sharing.ID]network.RoundMessages[BcastT],
) {
	t.Helper()
	broadcastInputs = make(map[sharing.ID]network.RoundMessages[BcastT], len(participants))
	for _, receiver := range participants {
		inputs := hashmap.NewComparable[sharing.ID, BcastT]()
		for _, sender := range participants {
			if sender.SharingID() == receiver.SharingID() {
				continue
			}
			msg := broadcastOutputs[sender.SharingID()]
			inputs.Put(sender.SharingID(), CBORRoundTrip(t, msg))
		}
		broadcastInputs[receiver.SharingID()] = inputs.Freeze()
	}
	return broadcastInputs
}

// MapUnicastO2I maps the P2P messages of all participants in a round of a protocol to the inputs of the next round
// with serializing and deserializing them throughout the process.
func MapUnicastO2I[
	P interface {
		SharingID() sharing.ID
	}, UnicastT network.Message,
](
	t testing.TB,
	participants []P,
	p2pOutputs map[sharing.ID]network.RoundMessages[UnicastT],
) (
	p2pInputs map[sharing.ID]network.RoundMessages[UnicastT],
) {
	p2pInputs = make(map[sharing.ID]network.RoundMessages[UnicastT], len(participants))
	for _, receiver := range participants {
		inputs := hashmap.NewComparable[sharing.ID, UnicastT]()
		for _, sender := range participants {
			if sender.SharingID() == receiver.SharingID() {
				continue
			}
			msg, exists := p2pOutputs[sender.SharingID()].Get(receiver.SharingID())
			require.True(t, exists)
			inputs.Put(sender.SharingID(), CBORRoundTrip(t, msg))
		}
		p2pInputs[receiver.SharingID()] = inputs.Freeze()

	}
	return p2pInputs
}
