package setup

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

// size should match zero.LambdaBytes.

type Round1P2P struct {
	Commitment commitments.Commitment

	_ ds.Incomparable
}

type Round2P2P struct {
	Message []byte
	Witness commitments.Witness

	_ ds.Incomparable
}

func (p *Participant) Round1() (types.RoundMessages[*Round1P2P], error) {
	if p.round != 1 {
		return nil, errs.NewRound("round mismatch %d != 1", p.round)
	}

	output := types.NewRoundMessages[*Round1P2P]()
	for _, participant := range p.SortedParticipants {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		participantIndex, exists := p.IdentitySpace.LookUpRight(participant)
		if !exists {
			return nil, errs.NewMissing("couldn't find participant %x in the identity space", participant.PublicKey().ToAffineCompressed())
		}
		randomBytes := przs.Seed{}
		if _, err := io.ReadFull(p.prng, randomBytes[:]); err != nil {
			return nil, errs.NewFailed("could not produce random bytes for party with index %d", participantIndex)
		}
		seedForThisParticipant, err := hashing.HashChain(base.CommitmentHashFunction, p.SessionId, randomBytes[:])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce seed for participant with index %d", participantIndex)
		}
		commitment, witness, err := commitments.Commit(
			p.SessionId,
			p.prng,
			seedForThisParticipant,
		)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not commit to the seed for participant with index %d", participantIndex)
		}
		p.state.sentSeeds.Put(participant, &committedSeedContribution{
			seed:       seedForThisParticipant,
			commitment: commitment,
			witness:    witness,
		})
		output.Put(participant, &Round1P2P{
			Commitment: commitment,
		})
	}
	p.round++
	return output, nil
}

func (p *Participant) Round2(round1output types.RoundMessages[*Round1P2P]) (types.RoundMessages[*Round2P2P], error) {
	if p.round != 2 {
		return nil, errs.NewRound("round mismatch %d != 2", p.round)
	}
	output := types.NewRoundMessages[*Round2P2P]()
	for _, participant := range p.SortedParticipants {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		participantIndex, exists := p.IdentitySpace.LookUpRight(participant)
		if !exists {
			return nil, errs.NewMissing("couldn't find participant %x in the identity space", participant.PublicKey().ToAffineCompressed())
		}
		message, exists := round1output.Get(participant)
		if !exists {
			return nil, errs.NewMissing("no message was received from participant with index %d", participantIndex)
		}
		if message.Commitment == nil {
			return nil, errs.NewMissing("participant with index %d sent empty commitment", participantIndex)
		}
		p.state.receivedSeeds.Put(participant, message.Commitment)
		contributed, exists := p.state.sentSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("missing what I contributed to participant with index %d", participantIndex)
		}
		output.Put(participant, &Round2P2P{
			Message: contributed.seed,
			Witness: contributed.witness,
		})
	}
	p.round++
	return output, nil
}

func (p *Participant) Round3(round2output types.RoundMessages[*Round2P2P]) (przs.PairWiseSeeds, error) {
	if p.round != 3 {
		return nil, errs.NewRound("round mismatch %d != 3", p.round)
	}
	myIndex, exists := p.IdentitySpace.LookUpRight(p.IdentityKey())
	if !exists {
		return nil, errs.NewMissing("couldn't find my identity index")
	}
	pairwiseSeeds := hashmap.NewHashableHashMap[types.IdentityKey, przs.Seed]()
	for _, participant := range p.SortedParticipants {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		participantIndex, exists := p.IdentitySpace.LookUpRight(participant)
		if !exists {
			return nil, errs.NewMissing("couldn't find participant %x in the identity space", participant.PublicKey().ToAffineCompressed())
		}
		message, exists := round2output.Get(participant)
		if !exists {
			return nil, errs.NewMissing("no message was received from participant with index %d", participantIndex)
		}
		commitment, exists := p.state.receivedSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("do not have a commitment from participant with index %d", participantIndex)
		}
		if message.Message == nil {
			return nil, errs.NewMissing("participant with index %d sent empty message", participantIndex)
		}
		if message.Witness == nil {
			return nil, errs.NewMissing("participant with index %d sent empty witness", participantIndex)
		}
		if err := commitments.Open(p.SessionId, commitment, message.Witness, message.Message); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, participantIndex, "commitment from participant with sharing id can't be opened")
		}
		myContributedSeed, exists := p.state.sentSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("what I contributed to the participant with sharing id %d is missing", participantIndex)
		}
		var orderedAppendedSeeds []byte
		if myIndex < participantIndex {
			orderedAppendedSeeds = append(myContributedSeed.seed, message.Message...)
		} else {
			orderedAppendedSeeds = append(message.Message, myContributedSeed.seed...)
		}
		finalSeedBytes, err := hashing.HashChain(base.CommitmentHashFunction, orderedAppendedSeeds)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce final seed for participant with sharing id %d", participantIndex)
		}
		finalSeed := przs.Seed{}
		copy(finalSeed[:], finalSeedBytes)
		pairwiseSeeds.Put(participant, finalSeed)
	}
	p.round++
	return pairwiseSeeds, nil
}
