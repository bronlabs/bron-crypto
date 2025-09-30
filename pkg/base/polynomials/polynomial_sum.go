package polynomials

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type DirectSumPolynomialRing[RE algebra.RingElement[RE]] struct {
	polyRing *PolynomialRing[RE]
	arity    int
}

func NewDirectSumPolynomialRing[RE algebra.RingElement[RE]](polyRing *PolynomialRing[RE], arity int) (*DirectSumPolynomialRing[RE], error) {
	if arity < 1 {
		return nil, errs.NewSize("arity must be greater than or equal to 1")
	}
	return &DirectSumPolynomialRing[RE]{
		polyRing: polyRing,
		arity:    arity,
	}, nil
}

func (r *DirectSumPolynomialRing[RE]) New(polys ...*Polynomial[RE]) (*DirectSumPolynomial[RE], error) {
	if len(polys) != r.arity {
		return nil, errs.NewSize("polynomial count does not match arity")
	}
	return &DirectSumPolynomial[RE]{
		polys: polys,
	}, nil
}

func (r *DirectSumPolynomialRing[RE]) Name() string {
	return fmt.Sprintf("DirectSumPolynomialRing[%s]", r.polyRing.Name())
}

func (r *DirectSumPolynomialRing[RE]) Order() crtp.Cardinal {
	//TODO implement me
	panic("implement me")
}

func (r *DirectSumPolynomialRing[RE]) Model() *universal.Model[*DirectSumPolynomial[RE]] {
	//TODO implement me
	panic("implement me")
}

func (r *DirectSumPolynomialRing[RE]) FromBytes(bytes []byte) (*DirectSumPolynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (r *DirectSumPolynomialRing[RE]) ElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (r *DirectSumPolynomialRing[RE]) Characteristic() crtp.Cardinal {
	//TODO implement me
	panic("implement me")
}

func (r *DirectSumPolynomialRing[RE]) OpIdentity() *DirectSumPolynomial[RE] {
	return r.Zero()
}

func (r *DirectSumPolynomialRing[RE]) One() *DirectSumPolynomial[RE] {
	polys := make([]*Polynomial[RE], r.arity)
	for i := 0; i < r.arity; i++ {
		polys[i] = r.polyRing.One()
	}
	return &DirectSumPolynomial[RE]{
		polys: polys,
	}
}

func (r *DirectSumPolynomialRing[RE]) Zero() *DirectSumPolynomial[RE] {
	polys := make([]*Polynomial[RE], r.arity)
	for i := 0; i < r.arity; i++ {
		polys[i] = r.polyRing.Zero()
	}
	return &DirectSumPolynomial[RE]{
		polys: polys,
	}
}

func (r *DirectSumPolynomialRing[RE]) IsSemiDomain() bool {
	//TODO implement me
	panic("implement me")
}

func (r *DirectSumPolynomialRing[RE]) Random(prng io.Reader) (*DirectSumPolynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (r *DirectSumPolynomialRing[RE]) Hash(bytes []byte) (*DirectSumPolynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

type DirectSumPolynomial[RE algebra.RingElement[RE]] struct {
	polys []*Polynomial[RE]
}

func (p *DirectSumPolynomial[RE]) Structure() crtp.Structure[*DirectSumPolynomial[RE]] {
	polyRing := p.polys[0].Structure().(*PolynomialRing[RE])
	r, err := NewDirectSumPolynomialRing(polyRing, len(p.polys))
	if err != nil {
		panic(err)
	}
	return r
}

func (p *DirectSumPolynomial[RE]) Bytes() []byte {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Clone() *DirectSumPolynomial[RE] {
	polys := make([]*Polynomial[RE], len(p.polys))
	for i, c := range p.polys {
		polys[i] = c.Clone()
	}
	return &DirectSumPolynomial[RE]{
		polys: polys,
	}
}

func (p *DirectSumPolynomial[RE]) Equal(rhs *DirectSumPolynomial[RE]) bool {
	if len(p.polys) != len(rhs.polys) {
		return false
	}
	for i := range p.polys {
		if !p.polys[i].Equal(rhs.polys[i]) {
			return false
		}
	}

	return true
}

func (p *DirectSumPolynomial[RE]) HashCode() base.HashCode {
	h := base.HashCode(0)
	for _, c := range p.polys {
		h ^= c.HashCode()
	}
	return h
}

func (p *DirectSumPolynomial[RE]) String() string {
	repr := "["
	for _, c := range p.polys {
		repr += fmt.Sprintf("%s, ", c.String())
	}
	repr += "]"
	return repr
}

func (p *DirectSumPolynomial[RE]) Op(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	return p.Add(e)
}

func (p *DirectSumPolynomial[RE]) OtherOp(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	return p.Mul(e)
}

func (p *DirectSumPolynomial[RE]) Add(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	polys := make([]*Polynomial[RE], len(p.polys))
	for i := range p.polys {
		polys[i] = p.polys[i].Add(e.polys[i])
	}
	return &DirectSumPolynomial[RE]{
		polys: polys,
	}
}

func (p *DirectSumPolynomial[RE]) Double() *DirectSumPolynomial[RE] {
	return p.Add(p)
}

func (p *DirectSumPolynomial[RE]) Mul(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	polys := make([]*Polynomial[RE], len(p.polys))
	for i := range p.polys {
		polys[i] = p.polys[i].Mul(e.polys[i])
	}
	return &DirectSumPolynomial[RE]{
		polys: polys,
	}
}

func (p *DirectSumPolynomial[RE]) Square() *DirectSumPolynomial[RE] {
	return p.Mul(p)
}

func (p *DirectSumPolynomial[RE]) IsOpIdentity() bool {
	return p.IsZero()
}

func (p *DirectSumPolynomial[RE]) TryOpInv() (*DirectSumPolynomial[RE], error) {
	return p.Neg(), nil
}

func (p *DirectSumPolynomial[RE]) IsOne() bool {
	for _, c := range p.polys {
		if !c.IsOne() {
			return false
		}
	}
	return true
}

func (p *DirectSumPolynomial[RE]) TryInv() (*DirectSumPolynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) TryDiv(e *DirectSumPolynomial[RE]) (*DirectSumPolynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) IsZero() bool {
	for _, c := range p.polys {
		if !c.IsZero() {
			return false
		}
	}
	return true
}

func (p *DirectSumPolynomial[RE]) TryNeg() (*DirectSumPolynomial[RE], error) {
	return p.Neg(), nil
}

func (p *DirectSumPolynomial[RE]) TrySub(e *DirectSumPolynomial[RE]) (*DirectSumPolynomial[RE], error) {
	return p.Sub(e), nil
}

func (p *DirectSumPolynomial[RE]) OpInv() *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Neg() *DirectSumPolynomial[RE] {
	polys := make([]*Polynomial[RE], len(p.polys))
	for i := range p.polys {
		polys[i] = p.polys[i].Neg()
	}
	return &DirectSumPolynomial[RE]{
		polys: polys,
	}
}

func (p *DirectSumPolynomial[RE]) Sub(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	return p.Add(e.Neg())
}

func (p *DirectSumPolynomial[RE]) Components() []*Polynomial[RE] {
	return p.polys
}
