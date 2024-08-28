package sample

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs"
)

func (p *Participant) Sample() (zeroShare rprzs.Sample, err error) {
	// step 1: initialise the zero share
	zeroShare = p.Protocol.Curve().ScalarField().Zero()
	myIndex, exists := p.IdentitySpace.Reverse().Get(p.IdentityKey())
	if !exists {
		return nil, errs.NewMissing("couldn't find my identity index")
	}
	for participant, prng := range p.Prngs.Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		// step 3: sample a random scalar for each participant
		sample, err := p.Protocol.Curve().ScalarField().Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not sample scalar")
		}
		i, exists := p.IdentitySpace.Reverse().Get(participant)
		if !exists {
			return nil, errs.NewMissing("couldn't find participant index")
		}
		// step 4: add the sample to the zero share
		if i < myIndex {
			zeroShare = zeroShare.Add(sample)
		} else {
			zeroShare = zeroShare.Add(sample.Neg())
		}
	}
	if zeroShare.IsZero() {
		return nil, errs.NewFailed("could not sample a zero share")
	}
	return zeroShare, nil
}
