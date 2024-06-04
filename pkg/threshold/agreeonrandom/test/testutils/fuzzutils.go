package agreeonrandom_testutils

import (
	"fmt"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom"
	"github.com/stretchr/testify/require"
)

func Run_HappyPath_AgreeOnRandom(t *testing.T, setup *AgreeOnRandomPublicParameters) {
	curve, identities, prng := setup.Curve, setup.Identities, setup.Prng
	participants := make([]*agreeonrandom.Participant, 0, len(identities))
	set := hashset.NewHashableHashSet(identities...)
	protocol, err := ttu.MakeProtocol(curve, identities)
	require.NoError(t, err, "couldn't make protocol")

	for iterator := set.Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
		participant, err := agreeonrandom.NewParticipant(identity.(types.AuthKey), protocol, nil, prng)
		require.NoError(t, err, "could not construct participant")

		participants = append(participants, participant)
	}

	r1Out, err := DoRound1(participants)
	require.NoError(t, err, "could not execute round 1")

	r2In := ttu.MapBroadcastO2I(participants, r1Out)
	r2Out, err := DoRound2(participants, r2In)
	require.NoError(t, err, "could not execute round 2")

	r3In := ttu.MapBroadcastO2I(participants, r2Out)
	agreeOnRandoms, err := DoRound3(participants, r3In)
	require.NoError(t, err, "could not execute round 3")

	require.Equal(t, len(agreeOnRandoms), set.Size(),
		fmt.Sprintf("expected %d agreeOnRandoms, got %d", len(identities), len(agreeOnRandoms)))

	// check all values in agreeOnRandoms the same
	for j := 1; j < len(agreeOnRandoms); j++ {
		require.Equal(t, len(agreeOnRandoms[0]), len(agreeOnRandoms[j]), "slices are not equal")
		for i := range agreeOnRandoms[0] {
			require.Equal(t, agreeOnRandoms[0][i], agreeOnRandoms[j][i], "slices are not equal")
		}
	}
}

func Run_UnhappyPath_AgreeonRandom_MockRound1(t *testing.T, setup *AgreeOnRandomPublicParameters) {
	t.Helper()
	var participants []*agreeonrandom.Participant
	protocol, err := ttu.MakeProtocol(setup.Curve, setup.Identities)
	require.NoError(t, err)
	for _, identity := range setup.Identities {
		var participant *agreeonrandom.Participant
		participant, _ = agreeonrandom.NewParticipant(identity.(types.AuthKey), protocol, nil, setup.Prng)
		participants = append(participants, participant)
	}

	r1Out, err := DoRound1(participants)
	require.NoError(t, err)
	r2In := ttu.MapBroadcastO2I(participants, r1Out)
	r2Out, err := DoRound2(participants, r2In)
	require.NoError(t, err)
	r3In := ttu.MapBroadcastO2I(participants, r2Out)
	agreeOnRandoms, err := DoRound3(participants, r3In)
	require.NoError(t, err)

	// check all values in agreeOnRandoms the same
	require.Len(t, agreeOnRandoms, len(setup.Identities))
	for i := 1; i < len(agreeOnRandoms); i++ {
		require.Equal(t, agreeOnRandoms[0], agreeOnRandoms[i])
	}
}
