package polynomials2

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
)

type DirectSumPolynomialRing[RE algebra.RingElement[RE]] struct {
	ring  FiniteRing[RE]
	arity int
}

func NewDirectSumPolynomialRing[RE algebra.RingElement[RE]](polyRing *PolynomialRing[RE], arity int) (*DirectSumPolynomialRing[RE], error) {
	return &DirectSumPolynomialRing[RE]{
		ring:  polyRing.ring,
		arity: arity,
	}, nil
}

func (r *DirectSumPolynomialRing[RE]) New(polys ...*Polynomial[RE]) (*DirectSumPolynomial[RE], error) {
	return &DirectSumPolynomial[RE]{
		polys: polys,
	}, nil
}

func (r *DirectSumPolynomialRing[RE]) Name() string {
	//TODO implement me
	panic("implement me")
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
	//TODO implement me
	panic("implement me")
}

func (r *DirectSumPolynomialRing[RE]) One() *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (r *DirectSumPolynomialRing[RE]) Zero() *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
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
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Bytes() []byte {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Clone() *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Equal(rhs *DirectSumPolynomial[RE]) bool {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) HashCode() base.HashCode {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) String() string {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Op(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) OtherOp(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Add(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Double() *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Mul(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Square() *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) IsOpIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) TryOpInv() (*DirectSumPolynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) IsOne() bool {
	//TODO implement me
	panic("implement me")
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
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) TryNeg() (*DirectSumPolynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) TrySub(e *DirectSumPolynomial[RE]) (*DirectSumPolynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) OpInv() *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Neg() *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Sub(e *DirectSumPolynomial[RE]) *DirectSumPolynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *DirectSumPolynomial[RE]) Components() []*Polynomial[RE] {
	return p.polys
}
