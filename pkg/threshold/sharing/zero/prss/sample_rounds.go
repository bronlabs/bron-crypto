package prss

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

func (p *SampleParticipant) Sample() curves.Scalar {
	x := p.cohortConfig.CipherSuite.Curve.ScalarField().New(uint64(p.mySharingId))
	sample := p.cohortConfig.CipherSuite.Curve.ScalarField().Zero()
	for _, subSet := range p.subSets {
		if subSet.Contains(p.myIdentity) {
			ra := p.ra[subSet.Label()] // TODO: use prf here
			fa := p.evalFa(subSet, x)
			sample = sample.Add(ra.Mul(fa))
		}
	}

	return sample
}

func (p *SampleParticipant) SampleZero() curves.Scalar {
	x := p.cohortConfig.CipherSuite.Curve.ScalarField().New(uint64(p.mySharingId))
	sample := p.cohortConfig.CipherSuite.Curve.ScalarField().Zero()
	for _, subSet := range p.subSets {
		if !subSet.Contains(p.myIdentity) {
			continue
		}
		ra := p.ra[subSet.Label()] // TODO: use prf here to make t pseudorandom values
		fa := p.evalFa(subSet, x)
		xi := p.cohortConfig.CipherSuite.Curve.ScalarField().One()
		subSample := p.cohortConfig.CipherSuite.Curve.ScalarField().Zero()
		for i := 0; i < p.t; i++ {
			xi = xi.Mul(x)
			subSample = subSample.Add(ra.Mul(xi).Mul(fa))
		}
		sample = sample.Add(subSample)
	}

	return sample
}

func (p *SampleParticipant) evalFa(subSet *SubSet, x curves.Scalar) curves.Scalar {
	xs := make([]curves.Scalar, 0)
	ys := make([]curves.Scalar, 0)

	xs = append(xs, p.cohortConfig.CipherSuite.Curve.ScalarField().Zero())
	ys = append(ys, p.cohortConfig.CipherSuite.Curve.ScalarField().One())

	for _, party := range p.cohortConfig.Participants.List() {
		if !subSet.Contains(party) {
			i := p.cohortConfig.CipherSuite.Curve.ScalarField().New(uint64(p.keyToId[party.Hash()]))
			xs = append(xs, i)
			ys = append(ys, p.cohortConfig.CipherSuite.Curve.ScalarField().Zero())
		}
	}

	dealer, _ := shamir.NewDealer(p.t+1, p.cohortConfig.Protocol.TotalParties, p.cohortConfig.CipherSuite.Curve)
	fa, _ := dealer.Interpolate(xs, ys, x)

	return fa
}
