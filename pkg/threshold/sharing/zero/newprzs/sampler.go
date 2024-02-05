package newprzs

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type Sampler struct {
	id      int
	t       int
	n       int
	field   curves.ScalarField
	subSets []int
	csprngs map[int]csprng.CSPRNG
}

func NewSampler(id, n, t int, field curves.ScalarField, a []byte, keys map[int]Key, seededPrngFactory csprng.CSPRNG) (*Sampler, error) {
	subSets := newSubSetsSet(n, n-t)
	csprngs := make(map[int]csprng.CSPRNG)
	for _, subSet := range subSets {
		var err error
		seed := keys[subSet]
		csprngs[subSet], err = seededPrngFactory.New(seed[:], a)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create seeded prng")
		}
	}

	sampler := &Sampler{
		id:      id,
		t:       t,
		n:       n,
		field:   field,
		subSets: subSets,
		csprngs: csprngs,
	}

	return sampler, nil
}

// Sample returns (t + 1, n) shamir sharing of some pseudorandom value.
func (p *Sampler) SampleRandom() (curves.Scalar, error) {
	x := p.field.New(uint64(p.id + 1))
	sample := p.field.Zero()
	for _, subSet := range p.subSets {
		if !subSetContains(subSet, p.id) {
			continue
		}

		random := make([]byte, base.ComputationalSecurityBytes+p.field.FieldBytes())
		_, err := io.ReadFull(p.csprngs[subSet], random)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot sample ra")
		}

		ra, err := p.field.Zero().SetBytesWide(random)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot sample ra")
		}

		fa := p.evalFa(subSet, x)

		subSample := ra.Mul(fa)
		sample = sample.Add(subSample)
	}

	return sample, nil
}

// SampleZero return (t + 2, n) shamir sharing of zero.
func (p *Sampler) SampleZero() (curves.Scalar, error) {
	x := p.field.New(uint64(p.id + 1))
	sample := p.field.Zero()
	for _, subSet := range p.subSets {
		if !subSetContains(subSet, p.id) {
			continue
		}

		random := make([]byte, base.ComputationalSecurityBytes+p.field.FieldBytes())
		_, err := io.ReadFull(p.csprngs[subSet], random)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot sample ra")
		}

		ra, err := p.field.Zero().SetBytesWide(random)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot sample ra")
		}

		fa := p.evalFa(subSet, x)

		// this is not a mistake, make polynomial of t+1 degree
		// so t+2 shares are needed to reconstruct secret
		subSample := ra.Mul(x).Mul(fa)
		sample = sample.Add(subSample)
	}

	return sample, nil
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
