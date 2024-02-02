package newprzn

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

func (p *SampleParticipant) Sample() curves.Scalar {
	sample := k256.NewCurve().ScalarField().Zero()
	for _, theSet := range p.maximalUnqualifiedSets {
		if theSet.Contains(p.myIdentity) {
			sample = sample.Add(p.ra[theSet.Label()].Mul(p.evalFa(theSet)))
		}
	}

	return sample
}

func (p *SampleParticipant) evalFa(set *PartySubSet) curves.Scalar {
	xs := make([]curves.Scalar, 1)
	ys := make([]curves.Scalar, 1)

	xs[0] = k256.NewCurve().ScalarField().Zero()
	ys[0] = k256.NewCurve().ScalarField().One()

	for _, party := range p.parties.List() {
		if !set.Contains(party) {
			i := k256.NewCurve().ScalarField().New(uint64(p.keyToId[party.Hash()]))
			xs = append(xs, i)
			ys = append(ys, k256.NewCurve().ScalarField().Zero())
		}
	}

	dealer, _ := shamir.NewDealer(p.threshold+1, p.parties.Len(), k256.NewCurve())
	shamirId := k256.NewCurve().ScalarField().New(uint64(p.mySharingId))
	f, _ := dealer.Interpolate(xs, ys, shamirId)

	return f
}
