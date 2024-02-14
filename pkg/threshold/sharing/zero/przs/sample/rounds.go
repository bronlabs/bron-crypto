package sample

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

func (p *Participant) Sample() (zeroShare przs.Sample, err error) {
	zeroShare = p.Protocol.Curve().ScalarField().Zero()
	myIndex, exists := p.IdentitySpace.LookUpRight(p.IdentityKey())
	if !exists {
		return nil, errs.NewMissing("couldn't find my identity index")
	}
	for pair := range p.Prngs.Iter() {
		participant := pair.Key
		prng := pair.Value
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sample, err := p.Protocol.Curve().ScalarField().Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not sample scalar")
		}
		i, exists := p.IdentitySpace.LookUpRight(participant)
		if !exists {
			return nil, errs.NewMissing("couldn't find participant index")
		}
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
