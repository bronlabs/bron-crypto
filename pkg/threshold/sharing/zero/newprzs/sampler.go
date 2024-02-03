package newprzs

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type Sampler struct {
	id      int
	t       int
	n       int
	keys    map[int]curves.Scalar
	subSets []int
	field   curves.ScalarField
}

func NewSampler(id, n, t int, keys map[int]curves.Scalar) *Sampler {
	subSets := newSubSetsSet(n, n-t)
	var field curves.ScalarField
	for _, v := range keys {
		field = v.ScalarField()
		break
	}

	sampler := &Sampler{
		id:      id,
		t:       t,
		n:       n,
		keys:    keys,
		subSets: subSets,
		field:   field,
	}

	return sampler
}

func (p *Sampler) SampleZero() curves.Scalar {
	x := p.field.New(uint64(p.id + 1))
	sample := p.field.Zero()
	for _, subSet := range p.subSets {
		if !subSetContains(subSet, p.id) {
			continue
		}
		ra := p.keys[subSet] // TODO: use prf here to make t pseudorandom values
		fa := p.evalFa(subSet, x)

		// this is not a mistake, make polynomial of t+1 degree
		subSample := ra.Mul(x).Mul(fa)
		sample = sample.Add(subSample)
	}

	return sample
}

func (p *Sampler) evalFa(subSet int, x curves.Scalar) curves.Scalar {
	xs := make([]curves.Scalar, 0)
	ys := make([]curves.Scalar, 0)

	xs = append(xs, p.field.Zero())
	ys = append(ys, p.field.One())

	for id := 0; id < p.n; id++ {
		if !subSetContains(subSet, id) {
			i := p.field.New(uint64(id + 1))
			xs = append(xs, i)
			ys = append(ys, p.field.Zero())
		}
	}

	dealer, _ := shamir.NewDealer(p.t+1, p.n, p.field.Curve())
	fa, _ := dealer.Interpolate(xs, ys, x)

	return fa
}
