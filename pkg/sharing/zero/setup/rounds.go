package setup

import (
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
)

// size should match zero.LambdaBytes.
var h = sha3.New256

type Round1P2P struct {
	Commitment commitments.Commitment

	_ helper_types.Incomparable
}

type Round2P2P struct {
	Message []byte
	Witness commitments.Witness

	_ helper_types.Incomparable
}

func (p *Participant) Round1() (map[helper_types.IdentityHash]*Round1P2P, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	output := map[helper_types.IdentityHash]*Round1P2P{}
	for _, participant := range p.Participants {
		sharingId := p.IdentityKeyToSharingId[participant.Hash()]
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
		p.state.sentSeeds[participant.Hash()] = &committedSeedContribution{
			seed:       seedForThisParticipant,
			commitment: commitment,
			witness:    witness,
		}
		output[participant.Hash()] = &Round1P2P{
			Commitment: commitment,
		}
	}
	p.round++
	return output, nil
}

func (p *Participant) Round2(round1output map[helper_types.IdentityHash]*Round1P2P) (map[helper_types.IdentityHash]*Round2P2P, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	output := map[helper_types.IdentityHash]*Round2P2P{}
	for _, participant := range p.Participants {
		sharingId := p.IdentityKeyToSharingId[participant.Hash()]
		if sharingId == p.MySharingId {
			continue
		}
		message, exists := round1output[participant.Hash()]
		if !exists {
			return nil, errs.NewMissing("no message was received from participant with sharing id %d", sharingId)
		}
		if message.Commitment == nil {
			return nil, errs.NewMissing("participant with sharingId %d sent empty commitment", sharingId)
		}
		p.state.receivedSeeds[participant.Hash()] = message.Commitment
		contributed, exists := p.state.sentSeeds[participant.Hash()]
		if !exists {
			return nil, errs.NewMissing("missing what I contributed to participant with sharing id %d", sharingId)
		}
		output[participant.Hash()] = &Round2P2P{
			Message: contributed.seed,
			Witness: contributed.witness,
		}
	}
	p.round++
	return output, nil
}

func (p *Participant) Round3(round2output map[helper_types.IdentityHash]*Round2P2P) (zero.PairwiseSeeds, error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	pairwiseSeeds := zero.PairwiseSeeds{}
	for _, participant := range p.Participants {
		sharingId := p.IdentityKeyToSharingId[participant.Hash()]
		if sharingId == p.MySharingId {
			continue
		}
		message, exists := round2output[participant.Hash()]
		if !exists {
			return nil, errs.NewMissing("no message was received from participant with sharing id %d", sharingId)
		}
		commitment, exists := p.state.receivedSeeds[participant.Hash()]
		if !exists {
			return nil, errs.NewMissing("do not have a commitment from participant with sharing id %d", sharingId)
		}
		if message.Message == nil {
			return nil, errs.NewMissing("participant with sharingId %d sent empty message", sharingId)
		}
		if message.Witness == nil {
			return nil, errs.NewMissing("participant with sharingId %d sent empty witness", sharingId)
		}
		if err := commitments.Open(h, message.Message, commitment, message.Witness); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, sharingId, "commitment from participant with sharing id can't be opened")
		}
		myContributedSeed, exists := p.state.sentSeeds[participant.Hash()]
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
		pairwiseSeeds[participant.Hash()] = finalSeed
	}
	p.round++
	return pairwiseSeeds, nil
}
