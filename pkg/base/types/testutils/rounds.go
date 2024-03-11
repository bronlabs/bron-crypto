package testutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

// TODO: Create generics for DoRoundX functions
// TODO: Create generics for RunProtocol functions

// MapO2I maps the outputs of all participants in a round of a protocol to the inputs of the next round.
func MapO2I[
	PartyT types.MPCParticipant, BcastT network.MessageLike, UnicastT network.MessageLike,
](
	participants []PartyT,
	broadcastOutputs []BcastT,
	UnicastOutputs []network.RoundMessages[UnicastT],
) (
	broadcastInputs []network.RoundMessages[BcastT],
	UnicastInputs []network.RoundMessages[UnicastT],
) {
	if len(broadcastOutputs) != 0 {
		broadcastInputs = MapBroadcastO2I(participants, broadcastOutputs)
	}
	if len(UnicastOutputs) != 0 {
		UnicastInputs = MapUnicastO2I(participants, UnicastOutputs)
	}
	return broadcastInputs, UnicastInputs
}

// MapBroadcastO2I maps the broadcasts of all participants in a round of a protocol to the inputs of the next round.
func MapBroadcastO2I[
	PartyT types.MPCParticipant, BcastT network.MessageLike,
](
	participants []PartyT,
	broadcastOutputs []BcastT,
) (
	broadcastInputs []network.RoundMessages[BcastT],
) {
	broadcastInputs = make([]network.RoundMessages[BcastT], len(participants))
	for i := range participants {
		broadcastInputs[i] = network.NewRoundMessages[BcastT]()
		for j := range participants {
			if j != i {
				broadcastInputs[i].Put(participants[j].IdentityKey(), broadcastOutputs[j])
			}
		}
	}
	return broadcastInputs
}

// MapUnicastO2I maps the P2P messages of all participants in a round of a protocol to the inputs of the next round.
func MapUnicastO2I[
	PartyT types.MPCParticipant, UnicastT network.MessageLike,
](
	participants []PartyT,
	UnicastOutputs []network.RoundMessages[UnicastT],
) (
	UnicastInputs []network.RoundMessages[UnicastT],
) {
	UnicastInputs = make([]network.RoundMessages[UnicastT], len(participants))
	for i := range participants {
		UnicastInputs[i] = network.NewRoundMessages[UnicastT]()
		for j := range participants {
			if j != i {
				msg, _ := UnicastOutputs[j].Get(participants[i].IdentityKey())
				UnicastInputs[i].Put(participants[j].IdentityKey(), msg)
			}
		}
	}
	return UnicastInputs
}
