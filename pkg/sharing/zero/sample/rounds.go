package sample

import (
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
)

func (p *Participant) Sample() (zero.Sample, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	sample := p.Curve.Scalar.Zero()
	// We need to sample a random value that is consistent with the seeds we received from the other participants.
	// Because we want to enforce that we abort if participants don't agree on who's present in the sampling phase.
	var presentParticipantIdentityKey []byte
	for _, participant := range p.PresentParticipants {
		presentParticipantIdentityKey = append(presentParticipantIdentityKey, participant.PublicKey().ToAffineCompressed()...)
	}
	for _, participant := range p.PresentParticipants {
		sharingId, exists := p.IdentityKeyToSharingId.Get(participant)
		if !exists {
			return nil, errs.NewFailed("could not find sharing id for participant %s", participant)
		}
		if sharingId == p.MySharingId {
			continue
		}
		sharedSeed, exists := p.Seeds.Get(participant)
		if !exists {
			return nil, errs.NewMissing("could not find shared seeds for sharing id %d", sharingId)
		}
		sampled := p.Curve.Scalar.Hash(p.UniqueSessionId, presentParticipantIdentityKey, sharedSeed[:])
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
