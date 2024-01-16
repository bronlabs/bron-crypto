package setup

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

// size should match zero.LambdaBytes.

type Round1P2P struct {
	Commitment commitments.Commitment

	_ types.Incomparable
}

type Round2P2P struct {
	Message []byte
	Witness commitments.Witness

	_ types.Incomparable
}

func (p *Participant) Round1() (map[types.IdentityHash]*Round1P2P, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	output := map[types.IdentityHash]*Round1P2P{}
	for _, participant := range p.SortedParticipants {
		sharingId := p.IdentityKeyToSharingId[participant.Hash()]
		if sharingId == p.MySharingId {
			continue
		}
		randomBytes := przs.Seed{}
		if _, err := p.prng.Read(randomBytes[:]); err != nil {
			return nil, errs.NewFailed("could not produce random bytes for party with sharing id %d", sharingId)
		}
		seedForThisParticipant, err := hashing.HashChain(base.CommitmentHashFunction, p.UniqueSessionId, randomBytes[:])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce seed for participant with sharing id %d", sharingId)
		}
		commitment, witness, err := commitments.Commit(
			p.UniqueSessionId,
			p.prng,
			seedForThisParticipant,
		)
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

func (p *Participant) Round2(round1output map[types.IdentityHash]*Round1P2P) (map[types.IdentityHash]*Round2P2P, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	output := map[types.IdentityHash]*Round2P2P{}
	for _, participant := range p.SortedParticipants {
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

func (p *Participant) Round3(round2output map[types.IdentityHash]*Round2P2P) (przs.PairwiseSeeds, error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	pairwiseSeeds := przs.PairwiseSeeds{}
	for _, participant := range p.SortedParticipants {
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
		if err := commitments.Open(p.UniqueSessionId, commitment, message.Witness, message.Message); err != nil {
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
		finalSeedBytes, err := hashing.HashChain(base.CommitmentHashFunction, orderedAppendedSeeds)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce final seed for participant with sharing id %d", sharingId)
		}
		finalSeed := przs.Seed{}
		copy(finalSeed[:], finalSeedBytes)
		pairwiseSeeds[participant.Hash()] = finalSeed
	}
	p.round++
	return pairwiseSeeds, nil
}
