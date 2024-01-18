package cogen_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/krypton/cogen"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, thresholdConfig := range []struct {
		n int
	}{
		{n: 2},
		{n: 3},
		{n: 5},
	} {
		boundedN := thresholdConfig.n
		t.Run(fmt.Sprintf("Happy path with n=%d", boundedN), func(t *testing.T) {
			t.Parallel()
			testHappyPath(t, boundedN)
		})
	}
}

func testHappyPath(t *testing.T, n int) {
	t.Helper()

	participants, err := makeParticipant(n)
	require.NoError(t, err)

	r1OutsB, err := doDkgRound1(participants)
	require.NoError(t, err)

	r2InsB := mapDkgRoundArray(participants, r1OutsB)
	r2OutsB, err := doDkgRound2(participants, r2InsB)
	require.NoError(t, err)

	r3InsB := mapDkgRoundArray(participants, r2OutsB)
	err = doDkgRound3(participants, r3InsB)
	require.NoError(t, err)
}

func doDkgRound3(participants []*cogen.Participant, r3InsB []map[types.IdentityHash]*cogen.Round2Broadcast) error {
	for i, participant := range participants {
		err := participant.Round3(r3InsB[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func doDkgRound2(participants []*cogen.Participant, round1BroadcastOutputs []map[types.IdentityHash]*cogen.Round1OutbandBroadcast) (round2BroadcastOutputs []*cogen.Round2Broadcast, err error) {
	round2BroadcastOutputs = make([]*cogen.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], err = participant.Round2(round1BroadcastOutputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2BroadcastOutputs, nil
}

func mapDkgRoundArray[T any](participants []*cogen.Participant, round2BroadcastOutputs []*T) (round2BroadcastInputs []map[types.IdentityHash]*T) {
	round2BroadcastInputs = make([]map[types.IdentityHash]*T, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[types.IdentityHash]*T)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetAuthKey().Hash()] = round2BroadcastOutputs[j]
			}
		}
	}
	return round2BroadcastInputs
}

func doDkgRound1(participants []*cogen.Participant) ([]*cogen.Round1OutbandBroadcast, error) {
	r1OutsB := make([]*cogen.Round1OutbandBroadcast, len(participants))
	var err error
	for i, participant := range participants {
		r1OutsB[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}
	return r1OutsB, nil
}

func makeParticipant(n int) ([]*cogen.Participant, error) {
	participants := make([]*cogen.Participant, n)
	for i := 0; i < n; i++ {
		participant, err := cogen.NewParticipant(func() (integration.AuthKey, error) {
			return NewCogenAuthKey(crand.Reader)
		}, func(publicKey curves.Point) (integration.IdentityKey, error) {
			return NewCogenIdentityKey(publicKey)
		})
		if err != nil {
			return nil, err
		}
		participants[i] = participant
	}
	return participants, nil
}
