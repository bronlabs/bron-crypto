package newprzs

import "github.com/copperexchange/krypton-primitives/pkg/base/curves"

func (p *SampleParticipant) Sample() curves.Scalar {
	return p.sampler.SampleZero()
}
