package testutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

// TODO: Create generics for DoRoundX functions
// TODO: Create generics for RunProtocol functions

// MapO2I maps the outputs of all participants in a round of a protocol to the inputs of the next round.
func MapO2I[
	PartyT types.MPCParticipant, BcastT any, UnicastT any,
](
	participants []PartyT,
	broadcastOutputs []BcastT,
	UnicastOutputs []types.RoundMessages[UnicastT],
) (
	broadcastInputs []types.RoundMessages[BcastT],
	UnicastInputs []types.RoundMessages[UnicastT],
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
	PartyT types.MPCParticipant, BcastT any,
](
	participants []PartyT,
	broadcastOutputs []BcastT,
) (
	broadcastInputs []types.RoundMessages[BcastT],
) {
	broadcastInputs = make([]types.RoundMessages[BcastT], len(participants))
	for i := range participants {
		broadcastInputs[i] = types.NewRoundMessages[BcastT]()
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
	PartyT types.MPCParticipant, UnicastT any,
](
	participants []PartyT,
	UnicastOutputs []types.RoundMessages[UnicastT],
) (
	UnicastInputs []types.RoundMessages[UnicastT],
) {
	UnicastInputs = make([]types.RoundMessages[UnicastT], len(participants))
	for i := range participants {
		UnicastInputs[i] = types.NewRoundMessages[UnicastT]()
		for j := range participants {
			if j != i {
				msg, _ := UnicastOutputs[j].Get(participants[i].IdentityKey())
				UnicastInputs[i].Put(participants[j].IdentityKey(), msg)
			}
		}
	}
	return UnicastInputs
}
