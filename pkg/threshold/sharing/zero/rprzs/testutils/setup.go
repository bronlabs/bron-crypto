package testutils

import (
	"io"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs/setup"
)

func MakeSetupParticipants(curve curves.Curve, identities []types.IdentityKey, prng io.Reader) (participants []*setup.Participant, err error) {
	participants = make([]*setup.Participant, len(identities))
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run agree on random")
	}
	protocol, err := testutils.MakeProtocol(curve, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "protocol could not be constructed")
	}
	for i, identity := range identities {
		participants[i], err = setup.NewParticipant(uniqueSessionId, identity.(types.AuthKey), protocol, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}
	return participants, nil
}

func DoSetupRound1(participants []*setup.Participant) (round2Outputs []network.RoundMessages[types.Protocol, *setup.Round1P2P], err error) {
	round2Outputs = make([]network.RoundMessages[types.Protocol, *setup.Round1P2P], len(participants))
	for i, participant := range participants {
		round2Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run Setup round 1")
		}
	}
	return round2Outputs, nil
}

func DoSetupRound2(participants []*setup.Participant, round3Inputs []network.RoundMessages[types.Protocol, *setup.Round1P2P]) (round3Outputs []network.RoundMessages[types.Protocol, *setup.Round2P2P], err error) {
	round3Outputs = make([]network.RoundMessages[types.Protocol, *setup.Round2P2P], len(participants))
	for i, participant := range participants {
		round3Outputs[i], err = participant.Round2(round3Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run Setup round 2")
		}
	}
	return round3Outputs, nil
}

func DoSetupRound3(participants []*setup.Participant, round4Inputs []network.RoundMessages[types.Protocol, *setup.Round2P2P]) (allPairwiseSeeds []rprzs.PairWiseSeeds, err error) {
	allPairwiseSeeds = make([]rprzs.PairWiseSeeds, len(participants))
	for i, participant := range participants {
		allPairwiseSeeds[i], err = participant.Round3(round4Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run Setup round 3")
		}
	}
	return allPairwiseSeeds, nil
}

func DoSetupRound1WithParallelParties(participants []*setup.Participant) (round1Outputs []network.RoundMessages[types.Protocol, *setup.Round1P2P], err error) {
	r1uOut := make(chan []network.RoundMessages[types.Protocol, *setup.Round1P2P])
	go func() {
		var wg sync.WaitGroup
		round1UnicastOutputs := make([]network.RoundMessages[types.Protocol, *setup.Round1P2P], len(participants))
		errch := make(chan error, len(participants))

		// Round 1
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *setup.Participant) {
				defer wg.Done()
				var err error
				round1UnicastOutputs[i], err = participant.Round1()
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 1")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		r1uOut <- round1UnicastOutputs
		close(r1uOut)
	}()
	return <-r1uOut, nil
}

func DoSetupRound2WithParallelParties(participants []*setup.Participant, round2Inputs []network.RoundMessages[types.Protocol, *setup.Round1P2P]) (round2Outputs []network.RoundMessages[types.Protocol, *setup.Round2P2P], err error) {
	r2uOut := make(chan []network.RoundMessages[types.Protocol, *setup.Round2P2P])
	go func() {
		var wg sync.WaitGroup
		round1UniCastOutputs := make([]network.RoundMessages[types.Protocol, *setup.Round2P2P], len(participants))
		errch := make(chan error, len(participants))

		// Round 1
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *setup.Participant) {
				defer wg.Done()
				var err error
				round1UniCastOutputs[i], err = participant.Round2(round2Inputs[i])
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 2")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		r2uOut <- round1UniCastOutputs
		close(r2uOut)
	}()
	return <-r2uOut, nil
}

func DoSetupRound3WithParallelParties(participants []*setup.Participant, round3Inputs []network.RoundMessages[types.Protocol, *setup.Round2P2P]) (allPairwiseSeeds []rprzs.PairWiseSeeds, err error) {
	allPairwiseSeedsChan := make(chan []rprzs.PairWiseSeeds)
	go func() {
		var wg sync.WaitGroup
		allPairwiseSeeds := make([]rprzs.PairWiseSeeds, len(participants))
		errch := make(chan error, len(participants))

		// Round 1
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *setup.Participant) {
				defer wg.Done()
				var err error
				allPairwiseSeeds[i], err = participant.Round3(round3Inputs[i])
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 3")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		allPairwiseSeedsChan <- allPairwiseSeeds
		close(allPairwiseSeedsChan)
	}()
	return <-allPairwiseSeedsChan, nil
}
