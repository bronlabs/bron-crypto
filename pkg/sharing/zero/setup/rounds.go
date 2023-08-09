package setup

import (
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
)

// size should match zero.LambdaBytes.
var h = sha3.New256

type Round1P2P struct {
	Commitment commitments.Commitment
}

type Round2P2P struct {
	Message []byte
	Witness commitments.Witness
}

func (p *Participant) Round1() (*hashmap.HashMap[integration.IdentityKey, *Round1P2P], error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	output := hashmap.NewHashMap[integration.IdentityKey, *Round1P2P]()
	for _, participant := range p.Participants {
		sharingId, exists := p.IdentityKeyToSharingId.Get(participant)
		if !exists {
			return nil, errs.NewFailed("could not find sharing id for participant %s", participant)
		}
		if sharingId == p.MySharingId {
			continue
		}
		randomBytes := zero.Seed{}
		if _, err := p.prng.Read(randomBytes[:]); err != nil {
			return nil, errs.NewFailed("could not produce random bytes for party with sharing id %d", sharingId)
		}
		seedForThisParticipant, err := hashing.Hash(h, p.UniqueSessionId, randomBytes[:])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce seed for participant with sharing id %d", sharingId)
		}
		commitment, witness, err := commitments.Commit(h, seedForThisParticipant)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not commit to the seed for participant with sharing id %d", sharingId)
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

func (p *Participant) Round2(round1output *hashmap.HashMap[integration.IdentityKey, *Round1P2P]) (*hashmap.HashMap[integration.IdentityKey, *Round2P2P], error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	output := hashmap.NewHashMap[integration.IdentityKey, *Round2P2P]()
	for _, participant := range p.Participants {
		sharingId, exists := p.IdentityKeyToSharingId.Get(participant)
		if !exists {
			return nil, errs.NewFailed("could not find sharing id for participant %s", participant)
		}
		if sharingId == p.MySharingId {
			continue
		}
		message, exists := round1output.Get(participant)
		if !exists {
			return nil, errs.NewMissing("no message was received from participant with sharing id %d", sharingId)
		}
		if message.Commitment == nil {
			return nil, errs.NewIdentifiableAbort("participant with sharingId %d sent empty commitment", sharingId)
		}
		p.state.receivedSeeds.Put(participant, message.Commitment)
		contributed, exists := p.state.sentSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("missing what I contributed to participant with sharing id %d", sharingId)
		}
		output.Put(participant, &Round2P2P{
			Message: contributed.seed,
			Witness: contributed.witness,
		})
	}
	p.round++
	return output, nil
}

func (p *Participant) Round3(round2output *hashmap.HashMap[integration.IdentityKey, *Round2P2P]) (zero.PairwiseSeeds, error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	pairwiseSeeds := zero.NewPairwiseSeeds()
	for _, participant := range p.Participants {
		sharingId, exists := p.IdentityKeyToSharingId.Get(participant)
		if !exists {
			return nil, errs.NewFailed("could not find sharing id for participant %s", participant)
		}
		if sharingId == p.MySharingId {
			continue
		}
		message, exists := round2output.Get(participant)
		if !exists {
			return nil, errs.NewMissing("no message was received from participant with sharing id %d", sharingId)
		}
		commitment, exists := p.state.receivedSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("do not have a commitment from participant with sharing id %d", sharingId)
		}
		if message.Message == nil {
			return nil, errs.NewIdentifiableAbort("participant with sharingId %d sent empty message", sharingId)
		}
		if message.Witness == nil {
			return nil, errs.NewIdentifiableAbort("participant with sharingId %d sent empty witness", sharingId)
		}
		if err := commitments.Open(h, message.Message, commitment, message.Witness); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "commitment from participant with sharing id %d can't be opened", sharingId)
		}
		myContributedSeed, exists := p.state.sentSeeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("what I contributed to the participant with sharing id %d is missing", sharingId)
		}
		var orderedAppendedSeeds []byte
		if p.MySharingId < sharingId {
			orderedAppendedSeeds = append(myContributedSeed.seed, message.Message...)
		} else {
			orderedAppendedSeeds = append(message.Message, myContributedSeed.seed...)
		}
		finalSeedBytes, err := hashing.Hash(h, orderedAppendedSeeds)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce final seed for participant with sharing id %d", sharingId)
		}
		finalSeed := zero.Seed{}
		copy(finalSeed[:], finalSeedBytes)
		pairwiseSeeds.Put(participant, finalSeed)
	}
	p.round++
	return pairwiseSeeds, nil
}
