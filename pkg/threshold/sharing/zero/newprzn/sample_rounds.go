package newprzn

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
)

func (p *SampleParticipant) Sample() curves.Scalar {
	sample := k256.NewCurve().ScalarField().Zero()
	i := k256.NewCurve().ScalarField().New(uint64(p.mySharingId))
	for _, theSet := range p.maximalUnqualifiedSets {
		if ra, ok := p.ra[theSet.Label()]; ok {
			sample = sample.Add(ra.Mul(p.evalFa(theSet, i)))
		}
	}

	return sample
}

func (p *SampleParticipant) evalFa(set *PartySubSet, x curves.Scalar) curves.Scalar {
	result := x.ScalarField().Curve().ScalarField().One()
	for _, party := range p.parties.List() {
		if !set.Contains(party) {
			i := k256.NewCurve().ScalarField().New(uint64(p.keyToId[party.Hash()]))
			if x.Cmp(i) == 0 {
				println("Ooops")
			}
			result.Mul(x.Sub(i))
		}
	}

	result = result.Add(x.ScalarField().Curve().ScalarField().One())
	if result.Cmp(x.ScalarField().Curve().ScalarField().Zero()) == 0 {
		println("Oops")
	}

	return result
}
