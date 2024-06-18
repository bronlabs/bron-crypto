package testutils

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom"
)

func MakeParticipants(n int) ([]*agreeonrandom.Participant, error) {
	identities, err := ttu.MakeDeterministicTestIdentities(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create identities")
	}

	// curve not used
	protocol, err := ttu.MakeProtocol(k256.NewCurve(), identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create protocol")
	}

	parties := make([]*agreeonrandom.Participant, n)
	for i, identity := range identities {
		parties[i], err = agreeonrandom.NewParticipant(identity.(types.AuthKey), protocol, nil, crand.Reader)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create participant")
		}
	}

	return parties, nil
}

func RunAgreeOnRandom(curve curves.Curve, identities []types.IdentityKey, prng io.Reader) ([]byte, error) {
	participants := make([]*agreeonrandom.Participant, 0, len(identities))
	set := hashset.NewHashableHashSet(identities...)
	protocol, err := ttu.MakeProtocol(curve, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't make protocol")
	}
	for iterator := set.Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
		participant, err := agreeonrandom.NewParticipant(identity.(types.AuthKey), protocol, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
		participants = append(participants, participant)
	}

	r1Out, err := DoRound1(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not execute round 1")
	}
	r2In := ttu.MapBroadcastO2I(participants, r1Out)
	r2Out, err := DoRound2(participants, r2In)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not execute round 2")
	}
	r3In := ttu.MapBroadcastO2I(participants, r2Out)
	agreeOnRandoms, err := DoRound3(participants, r3In)

	if err != nil {
		return nil, errs.WrapFailed(err, "could not execute round 3")
	}
	if len(agreeOnRandoms) != set.Size() {
		return nil, errs.NewArgument("expected %d agreeOnRandoms, got %d", len(identities), len(agreeOnRandoms))
	}

	// check all values in agreeOnRandoms the same
	for j := 1; j < len(agreeOnRandoms); j++ {
		if len(agreeOnRandoms[0]) != len(agreeOnRandoms[j]) {
			return nil, errs.NewLength("slices are not equal")
		}

		for i := range agreeOnRandoms[0] {
			if agreeOnRandoms[0][i] != agreeOnRandoms[j][i] {
				return nil, errs.NewLength("slices are not equal")
			}
		}
	}

	return agreeOnRandoms[0], nil
}

func DoRound1(participants []*agreeonrandom.Participant) (round1Outputs []*agreeonrandom.Round1Broadcast, err error) {
	round1Outputs = make([]*agreeonrandom.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not execute round 1 for participant %d", i)
		}
	}
	return round1Outputs, nil
}

func DoRound2(participants []*agreeonrandom.Participant, round2Inputs []network.RoundMessages[types.Protocol, *agreeonrandom.Round1Broadcast]) (round2Outputs []*agreeonrandom.Round2Broadcast, err error) {
	round2Outputs = make([]*agreeonrandom.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2Outputs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not execute round 2 for participant %d", i)
		}
	}
	return round2Outputs, nil
}

func DoRound3(participants []*agreeonrandom.Participant, round2Inputs []network.RoundMessages[types.Protocol, *agreeonrandom.Round2Broadcast]) (results [][]byte, err error) {
	results = make([][]byte, len(participants))
	for i, participant := range participants {
		results[i], err = participant.Round3(round2Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not execute round 3 for participant %d", i)
		}
	}
	return results, nil
}
