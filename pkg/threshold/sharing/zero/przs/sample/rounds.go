package sample

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

func (p *Participant) Sample() (zeroShare przs.Sample, err error) {
	zeroShare = p.Curve.ScalarField().Zero()
	for sharingId := range p.Prngs {
		sample, err := p.Curve.ScalarField().Random(p.Prngs[sharingId])
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "could not sample scalar")
		}
		switch TheirSharingId := sharingId; {
		case TheirSharingId == p.MySharingId:
			return nil, errs.NewInvalidArgument("cannot sample with myself")
		case TheirSharingId < p.MySharingId:
			zeroShare = zeroShare.Add(sample)
		default:
			zeroShare = zeroShare.Add(sample.Neg())
		}
	}
	if zeroShare.IsZero() {
		return nil, errs.NewFailed("could not sample a zero share")
	}
	return zeroShare, nil
}
