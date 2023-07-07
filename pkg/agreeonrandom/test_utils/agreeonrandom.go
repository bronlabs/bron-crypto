package test_utils

import (
	"testing"

	crand "crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/stretchr/testify/require"
)

func DoRounds(t *testing.T, curve *curves.Curve, identities []integration.IdentityKey, n int) []byte {
	t.Helper()
	var participants []*agreeonrandom.Participant
	for _, identity := range identities {
		participant, _ := agreeonrandom.NewParticipant(curve, identity, identities, nil, crand.Reader)
		participants = append(participants, participant)
	}

	r1Out, err := DoRound1(participants)
	require.NoError(t, err)
	r2In := MapRound1OutputsToRound2Inputs(participants, r1Out)
	agreeOnRandoms, err := DoRound2(participants, r2In)
	require.NoError(t, err)
	require.Len(t, agreeOnRandoms, len(identities))

	// check all values in agreeOnRandoms the same
	for i := 1; i < len(agreeOnRandoms); i++ {
		require.Equal(t, agreeOnRandoms[0], agreeOnRandoms[i])
	}

	return agreeOnRandoms[0]
}

func DoRound1(participants []*agreeonrandom.Participant) (round1Outputs []*agreeonrandom.Round1Broadcast, err error) {
	round1Outputs = make([]*agreeonrandom.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}
	return round1Outputs, nil
}

func MapRound1OutputsToRound2Inputs(participants []*agreeonrandom.Participant, round1Outputs []*agreeonrandom.Round1Broadcast) (round2Inputs []map[integration.IdentityKey]*agreeonrandom.Round1Broadcast) {
	round2Inputs = make([]map[integration.IdentityKey]*agreeonrandom.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityKey]*agreeonrandom.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey] = round1Outputs[j]
			}
		}
	}
	return round2Inputs
}

func DoRound2(participants []*agreeonrandom.Participant, round2Inputs []map[integration.IdentityKey]*agreeonrandom.Round1Broadcast) (results [][]byte, err error) {
	results = make([][]byte, len(participants))
	for i, participant := range participants {
		results[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}
