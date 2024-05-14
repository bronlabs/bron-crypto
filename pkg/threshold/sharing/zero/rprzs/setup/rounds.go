package setup

import (
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs"
)

func (p *Participant) Round1() (network.RoundMessages[types.Protocol, *Round1P2P], error) {
	// Validation
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	output := network.NewRoundMessages[types.Protocol, *Round1P2P]()
	for _, participant := range p.SortedParticipants {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		participantIndex, exists := p.IdentitySpace.Reverse().Get(participant)
		if !exists {
			return nil, errs.NewMissing("couldn't find participant %x in the identity space", participant.String())
		}
		// step 1.1: produce a random seed for this participant
		seedForThisParticipant := rprzs.Seed{}
		if _, err := io.ReadFull(p.Prng, seedForThisParticipant[:]); err != nil {
			return nil, errs.WrapRandomSample(err, "could not produce random bytes for party with index %d", participantIndex)
		}
		// step 1.2: commit to the seed
		committer, err := hashcomm.NewCommitter(p.SessionId, p.Prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot instantiate committer")
		}
		commitment, opening, err := committer.Commit(seedForThisParticipant[:])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not commit to the seed for participant with index %d", participantIndex)
		}
		p.state.sentSeeds.Put(participant, &committedSeedContribution{
			seed:       seedForThisParticipant[:],
			commitment: commitment,
			opening:    opening,
		})
		// step 1.3: send the commitment to the participant
		output.Put(participant, &Round1P2P{
			Commitment: commitment,
		})
	}

	p.Round++
	return output, nil
}

func (p *Participant) Round2(round1output network.RoundMessages[types.Protocol, *Round1P2P]) (network.RoundMessages[types.Protocol, *Round2P2P], error) {
	// Validation
	if p.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), round1output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 1 messages")
	}

	output := network.NewRoundMessages[types.Protocol, *Round2P2P]()
	for _, participant := range p.SortedParticipants {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		participantIndex, exists := p.IdentitySpace.Reverse().Get(participant)
		if !exists {
			return nil, errs.NewMissing("couldn't find participant %x in the identity space", participant.String())
		}
		message, _ := round1output.Get(participant)
		p.state.receivedSeeds.Put(participant, message.Commitment)
		contributed, exists := p.state.sentSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("missing what I contributed to participant with index %d", participantIndex)
		}
		// step 2.1: send the seed and the witness to the participant
		output.Put(participant, &Round2P2P{
			Message: contributed.seed,
			Opening: contributed.opening,
		})
	}

	p.Round++
	return output, nil
}

func (p *Participant) Round3(round2output network.RoundMessages[types.Protocol, *Round2P2P]) (rprzs.PairWiseSeeds, error) {
	// Validation
	if p.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), round2output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 messages")
	}

	myIndex, exists := p.IdentitySpace.Reverse().Get(p.IdentityKey())
	if !exists {
		return nil, errs.NewMissing("couldn't find my identity index")
	}
	pairwiseSeeds := hashmap.NewHashableHashMap[types.IdentityKey, rprzs.Seed]()
	for _, participant := range p.SortedParticipants {
		// step 3.1: open the commitment from the participant and verify it
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		participantIndex, exists := p.IdentitySpace.Reverse().Get(participant)
		if !exists {
			return nil, errs.NewMissing("couldn't find participant %x in the identity space", participant.String())
		}
		message, _ := round2output.Get(participant)
		commitment, exists := p.state.receivedSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("do not have a commitment from participant with index %d", participantIndex)
		}

		verifier := hashcomm.NewVerifier(p.SessionId)
		if err := verifier.Verify(commitment, message.Opening); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, participant.String(), "commitment from participant with sharing id can't be opened")
		}
		myContributedSeed, exists := p.state.sentSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("what I contributed to the participant with sharing id %d is missing", participantIndex)
		}
		// step 3.2: combine to produce the final seed
		var orderedAppendedSeeds []byte
		if myIndex < participantIndex {
			orderedAppendedSeeds = slices.Concat(myContributedSeed.seed, message.Message)
		} else {
			orderedAppendedSeeds = slices.Concat(message.Message, myContributedSeed.seed)
		}
		finalSeedBytes, err := hashing.HashChain(base.RandomOracleHashFunction, orderedAppendedSeeds)
		if err != nil {
			return nil, errs.WrapHashing(err, "could not produce final seed for participant with sharing id %d", participantIndex)
		}
		finalSeed := rprzs.Seed{}
		copy(finalSeed[:], finalSeedBytes)
		pairwiseSeeds.Put(participant, finalSeed)
	}

	p.Round++
	return pairwiseSeeds, nil
}
