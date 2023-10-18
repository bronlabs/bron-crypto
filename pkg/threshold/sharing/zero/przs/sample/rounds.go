package sample

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

func (p *Participant) Sample() (zeroShare przs.Sample, err error) {
	zeroShare = p.Curve.Scalar().Zero()
	for sharingId := range p.Prngs {
		sample := p.Curve.Scalar().Random(p.Prngs[sharingId])
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
