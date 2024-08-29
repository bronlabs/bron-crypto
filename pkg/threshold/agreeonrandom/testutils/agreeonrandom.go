package testutils

import (
	crand "crypto/rand"
	"io"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"

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

func RunAgreeOnRandomWithParallelParties(curve curves.Curve, identities []types.IdentityKey, prng io.Reader) ([]byte, error) {
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

	r1bOut := make(chan []*agreeonrandom.Round1Broadcast)
	go func() {
		var wg sync.WaitGroup
		round1BroadcastOutputs := make([]*agreeonrandom.Round1Broadcast, len(participants))
		errch := make(chan error, len(participants))

		// Round 1
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *agreeonrandom.Participant) {
				defer wg.Done()
				var err error
				round1BroadcastOutputs[i], err = participant.Round1()
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 1")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		r1bOut <- round1BroadcastOutputs
		close(r1bOut)
	}()

	r2In := ttu.MapBroadcastO2I(participants, <-r1bOut)
	r2bOut := make(chan []*agreeonrandom.Round2Broadcast)
	go func() {
		var wg sync.WaitGroup
		round2BroadcastOutputs := make([]*agreeonrandom.Round2Broadcast, len(participants))
		errch := make(chan error, len(participants))
		// Round 2
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *agreeonrandom.Participant) {
				defer wg.Done()
				var err error
				round2BroadcastOutputs[i], err = participant.Round2(r2In[i])
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 2")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		r2bOut <- round2BroadcastOutputs
		close(r2bOut)
	}()

	r3In := ttu.MapBroadcastO2I(participants, <-r2bOut)
	agreeOnRandoms := make(chan [][]byte)
	go func() {
		var wg sync.WaitGroup
		r3Out := make([][]byte, len(participants))
		errch := make(chan error, len(participants))
		// Round 2
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *agreeonrandom.Participant) {
				defer wg.Done()
				var err error
				r3Out[i], err = participant.Round3(r3In[i])
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 3")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		agreeOnRandoms <- r3Out
		close(agreeOnRandoms)
	}()

	agrOnRndm := <-agreeOnRandoms

	if len(agrOnRndm) != set.Size() {
		return nil, errs.NewArgument("expected %d agreeOnRandoms, got %d", len(identities), len(agrOnRndm))
	}

	// check all values in agreeOnRandoms the same
	for j := 1; j < len(agrOnRndm); j++ {
		if len(agrOnRndm[0]) != len(agrOnRndm[j]) {
			return nil, errs.NewLength("slices are not equal")
		}

		for i := range agrOnRndm[0] {
			if agrOnRndm[0][i] != agrOnRndm[j][i] {
				return nil, errs.NewLength("slices are not equal")
			}
		}
	}

	return agrOnRndm[0], nil
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
