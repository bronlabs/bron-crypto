package sample

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

func (p *Participant) Sample() (zeroShare przs.Sample, err error) {
	zeroShare = p.Curve.Scalar().Zero()
	zeroShareBytes := make([]byte, impl.FieldBytes)
	for sharingId := range p.Prngs {
		if _, err := p.Prngs[sharingId].Read(zeroShareBytes); err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "could not read from prng")
		}
		sample, err := p.Curve.Scalar().SetBytes(zeroShareBytes)
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "could not set bytes from prng")
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
