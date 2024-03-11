package setup

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

func (p *Participant) Round1() (network.RoundMessages[*Round1P2P], error) {
	// Validation
	if err := p.InRound(1); err != nil {
		return nil, errs.Forward(err)
	}

	output := network.NewRoundMessages[*Round1P2P]()
	for _, participant := range p.SortedParticipants {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		participantIndex, exists := p.IdentitySpace.Reverse().Get(participant)
		if !exists {
			return nil, errs.NewMissing("couldn't find participant %x in the identity space", participant.String())
		}
		// step 1.1: produce a random seed for this participant
		seedForThisParticipant := przs.Seed{}
		if _, err := io.ReadFull(p.Prng(), seedForThisParticipant[:]); err != nil {
			return nil, errs.WrapRandomSample(err, "could not produce random bytes for party with index %d", participantIndex)
		}
		// step 1.2: commit to the seed
		commitment, witness, err := commitments.Commit(
			p.SessionId(),
			p.Prng(),
			seedForThisParticipant[:],
		)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not commit to the seed for participant with index %d", participantIndex)
		}
		p.state.sentSeeds.Put(participant, &committedSeedContribution{
			seed:       seedForThisParticipant[:],
			commitment: commitment,
			witness:    witness,
		})
		// step 1.3: send the commitment to the participant
		output.Put(participant, &Round1P2P{
			Commitment: commitment,
		})
	}

	p.NextRound()
	return output, nil
}

func (p *Participant) Round2(round1output network.RoundMessages[*Round1P2P]) (network.RoundMessages[*Round2P2P], error) {
	// Validation
	if err := p.InRound(2); err != nil {
		return nil, errs.Forward(err)
	}
	if err := network.ValidateMessages(p.Protocol().Participants(), p.IdentityKey(), round1output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 1 messages")
	}

	output := network.NewRoundMessages[*Round2P2P]()
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
			Witness: contributed.witness,
		})
	}

	p.NextRound()
	return output, nil
}

func (p *Participant) Round3(round2output network.RoundMessages[*Round2P2P]) (przs.PairWiseSeeds, error) {
	// Validation
	if err := p.InRound(3); err != nil {
		return nil, errs.Forward(err)
	}
	if err := network.ValidateMessages(p.Protocol().Participants(), p.IdentityKey(), round2output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 messages")
	}

	myIndex, exists := p.IdentitySpace.Reverse().Get(p.IdentityKey())
	if !exists {
		return nil, errs.NewMissing("couldn't find my identity index")
	}
	pairwiseSeeds := hashmap.NewHashableHashMap[types.IdentityKey, przs.Seed]()
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
		if err := commitments.Open(p.SessionId(), commitment, message.Witness, message.Message); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, participant.String(), "commitment from participant with sharing id can't be opened")
		}
		myContributedSeed, exists := p.state.sentSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("what I contributed to the participant with sharing id %d is missing", participantIndex)
		}
		// step 3.2: combine to produce the final seed
		var orderedAppendedSeeds []byte
		if myIndex < participantIndex {
			orderedAppendedSeeds = append(myContributedSeed.seed, message.Message...)
		} else {
			orderedAppendedSeeds = append(message.Message, myContributedSeed.seed...)
		}
		finalSeedBytes, err := hashing.HashChain(commitments.CommitmentHashFunction, orderedAppendedSeeds)
		if err != nil {
			return nil, errs.WrapHashing(err, "could not produce final seed for participant with sharing id %d", participantIndex)
		}
		finalSeed := przs.Seed{}
		copy(finalSeed[:], finalSeedBytes)
		pairwiseSeeds.Put(participant, finalSeed)
	}

	p.LastRound()
	return pairwiseSeeds, nil
}
