package newprzs

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func (p *SampleParticipant) Sample() (curves.Scalar, error) {
	zeroSample, err := p.sampler.SampleZero()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot sample zero share")
	}

	return zeroSample, nil
}
