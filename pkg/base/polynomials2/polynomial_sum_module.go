package polynomials2

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
)

var _ algebra.ModuleElement[*ModuleValuedDirectSumPolynomial[*k256.Point, *k256.Scalar], *k256.Scalar] = (*ModuleValuedDirectSumPolynomial[*k256.Point, *k256.Scalar])(nil)

type ModuleValuedDirectSumPolynomial[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	zero  ME
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
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) Equal(rhs *ModuleValuedDirectSumPolynomial[ME, S]) bool {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) HashCode() base.HashCode {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) String() string {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) Op(e *ModuleValuedDirectSumPolynomial[ME, S]) *ModuleValuedDirectSumPolynomial[ME, S] {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) IsOpIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) TryOpInv() (*ModuleValuedDirectSumPolynomial[ME, S], error) {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) OpInv() *ModuleValuedDirectSumPolynomial[ME, S] {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) ScalarOp(actor S) *ModuleValuedDirectSumPolynomial[ME, S] {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) IsTorsionFree() bool {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedDirectSumPolynomial[ME, S]) CoDiagonal() *ModuleValuedPolynomial[ME, S] {
	return p.polys[0].Op(p.polys[1])
}

func LiftDirectSumPolynomial[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]](poly *DirectSumPolynomial[S], bases ...algebra.ModuleElement[ME, S]) (*ModuleValuedDirectSumPolynomial[ME, S], error) {
	zero := algebra.StructureMustBeAs[algebra.Module[ME, S]](bases[0].Structure()).OpIdentity()
	polys := make([]*ModuleValuedPolynomial[ME, S], len(poly.polys))
	for i := 0; i < len(poly.polys); i++ {
		var err error
		polys[i], err = LiftPolynomial(poly.polys[i], bases[i])
		if err != nil {
			return nil, err
		}
	}

	return &ModuleValuedDirectSumPolynomial[ME, S]{
		zero:  zero,
		polys: polys,
	}, nil
}
