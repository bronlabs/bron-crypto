package polynomials

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
)

var _ algebra.ModuleElement[*ModuleValuedDirectSumPolynomial[*k256.Point, *k256.Scalar], *k256.Scalar] = (*ModuleValuedDirectSumPolynomial[*k256.Point, *k256.Scalar])(nil)

type ModuleValuedDirectSumPolynomial[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	polys []*ModuleValuedPolynomial[ME, S]
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) Structure() crtp.Structure[*ModuleValuedDirectSumPolynomial[ME, S]] {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) Bytes() []byte {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) Clone() *ModuleValuedDirectSumPolynomial[ME, S] {
	polys := make([]*ModuleValuedPolynomial[ME, S], len(p.polys))
	for i, c := range p.polys {
		polys[i] = c.Clone()
	}
	return &ModuleValuedDirectSumPolynomial[ME, S]{
		polys: polys,
	}
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) Equal(rhs *ModuleValuedDirectSumPolynomial[ME, S]) bool {
	for i := range p.polys {
		if !p.polys[i].Equal(rhs.polys[i]) {
			return false
		}
	}

	return true
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) HashCode() base.HashCode {
	h := base.HashCode(0)
	for i := range p.polys {
		h ^= p.polys[i].HashCode()
	}
	return h
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) String() string {
	repr := "["
	for _, c := range p.polys {
		repr += fmt.Sprintf("%s,", c.String())
	}
	repr += "]"
	return repr
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) Op(e *ModuleValuedDirectSumPolynomial[ME, S]) *ModuleValuedDirectSumPolynomial[ME, S] {
	polys := make([]*ModuleValuedPolynomial[ME, S], len(p.polys))
	for i := range p.polys {
		polys[i] = p.polys[i].Op(e.polys[i])
	}
	return &ModuleValuedDirectSumPolynomial[ME, S]{
		polys: polys,
	}
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) IsOpIdentity() bool {
	for _, c := range p.polys {
		if !c.IsOpIdentity() {
			return false
		}
	}

	return true
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) TryOpInv() (*ModuleValuedDirectSumPolynomial[ME, S], error) {
	return p.OpInv(), nil
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) OpInv() *ModuleValuedDirectSumPolynomial[ME, S] {
	polys := make([]*ModuleValuedPolynomial[ME, S], len(p.polys))
	for i, c := range p.polys {
		polys[i] = c.OpInv()
	}
	return &ModuleValuedDirectSumPolynomial[ME, S]{
		polys: polys,
	}
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) ScalarOp(actor S) *ModuleValuedDirectSumPolynomial[ME, S] {
	polys := make([]*ModuleValuedPolynomial[ME, S], len(p.polys))
	for i, c := range p.polys {
		polys[i] = c.ScalarOp(actor)
	}
	return &ModuleValuedDirectSumPolynomial[ME, S]{
		polys: polys,
	}
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) IsTorsionFree() bool {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) CoDiagonal() *ModuleValuedPolynomial[ME, S] {
	return p.polys[0].Op(p.polys[1])
}

func LiftDirectSumPolynomial[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]](poly *DirectSumPolynomial[S], bases ...algebra.ModuleElement[ME, S]) (*ModuleValuedDirectSumPolynomial[ME, S], error) {
	polys := make([]*ModuleValuedPolynomial[ME, S], len(poly.polys))
	for i := 0; i < len(poly.polys); i++ {
		var err error
		polys[i], err = LiftPolynomial(poly.polys[i], bases[i])
		if err != nil {
			return nil, err
		}
	}

	return &ModuleValuedDirectSumPolynomial[ME, S]{
		polys: polys,
	}, nil
}
