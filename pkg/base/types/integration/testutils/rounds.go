package testutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

// TODO: Create generics for DoRoundX functions
// TODO: Create generics for RunProtocol functions

// MapO2I maps the outputs of all participants in a round of a protocol to the inputs of the next round.
func MapO2I[
	PartyT integration.Participant, BcastT any, UnicastT any,
](
	participants []PartyT,
	broadcastOutputs []BcastT,
	UnicastOutputs []map[types.IdentityHash]UnicastT,
) (
	broadcastInputs []map[types.IdentityHash]BcastT,
	UnicastInputs []map[types.IdentityHash]UnicastT,
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
	PartyT integration.Participant, BcastT any,
](
	participants []PartyT,
	broadcastOutputs []BcastT,
) (
	broadcastInputs []map[types.IdentityHash]BcastT,
) {
	broadcastInputs = make([]map[types.IdentityHash]BcastT, len(participants))
	for i := range participants {
		broadcastInputs[i] = make(map[types.IdentityHash]BcastT)
		for j := range participants {
			if j != i {
				broadcastInputs[i][participants[j].GetIdentityKey().Hash()] = broadcastOutputs[j]
			}
		}
	}
	return broadcastInputs
}

// MapUnicastO2I maps the P2P messages of all participants in a round of a protocol to the inputs of the next round.
func MapUnicastO2I[
	PartyT integration.Participant, UnicastT any,
](
	participants []PartyT,
	UnicastOutputs []map[types.IdentityHash]UnicastT,
) (
	UnicastInputs []map[types.IdentityHash]UnicastT,
) {
	UnicastInputs = make([]map[types.IdentityHash]UnicastT, len(participants))
	for i := range participants {
		UnicastInputs[i] = make(map[types.IdentityHash]UnicastT)
		for j := range participants {
			if j != i {
				UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}
	return UnicastInputs
}
