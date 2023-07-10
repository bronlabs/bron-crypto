package sample

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
)

func (p *Participant) Sample() (zero.Sample, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	sample := p.Curve.Scalar.Zero()
	var presentSharedSeeds []byte
	for _, participant := range p.PresentParticipants {
		presentSharedSeeds = append(presentSharedSeeds, participant.PublicKey().Scalar().Bytes()...)
	}
	for _, participant := range p.PresentParticipants {
		sharingId := p.IdentityKeyToSharingId[participant]
		if sharingId == p.MySharingId {
			continue
		}
		sharedSeed, exists := p.Seeds[participant]
		if !exists {
			return nil, errs.NewMissing("could not find shared seeds for sharing id %d", sharingId)
		}
		sumSharedSeeds := append(presentSharedSeeds, sharedSeed[:]...)
		// TODO: make hash to curve and scalars variadic
		toBeHashed := append(p.uniqueSessionId, sumSharedSeeds[:]...)
		sampled := p.Curve.Scalar.Hash(toBeHashed)
		if p.MySharingId < sharingId {
			sample = sample.Add(sampled)
		} else {
			sample = sample.Add(sampled.Neg())
		}
	}
	if sample.IsZero() {
		return nil, errs.NewFailed("could not sample a zero share")
	}
	p.round++
	return sample, nil
}
