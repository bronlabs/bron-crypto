package polynomials2

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
)

type FiniteRing[RE algebra.RingElement[RE]] interface {
	algebra.Ring[RE]
	algebra.FiniteStructure[RE]
}

var _ algebra.Ring[*Polynomial[*k256.Scalar]] = (*PolynomialRing[*k256.Scalar])(nil)
var _ algebra.RingElement[*Polynomial[*k256.Scalar]] = (*Polynomial[*k256.Scalar])(nil)

type PolynomialRing[RE algebra.RingElement[RE]] struct {
	ring FiniteRing[RE]
}

func (r *PolynomialRing[RE]) NewRandomWithConstantTerm(degree int, constantTerm RE, prng io.Reader) (*Polynomial[RE], error) {
	coeffs := make([]RE, degree+1)
	coeffs[0] = constantTerm.Clone()
	for i := 1; i <= degree; i++ {
		var err error
		coeffs[i], err = r.ring.Random(prng)
		if err != nil {
			return nil, err
		}
	}

	p := &Polynomial[RE]{
		coeffs: coeffs,
	}
	return p, nil
}

func (r *PolynomialRing[RE]) Name() string {
	//TODO implement me
	panic("implement me")
}

func (r *PolynomialRing[RE]) Order() crtp.Cardinal {
	//TODO implement me
	panic("implement me")
}

func (r *PolynomialRing[RE]) Model() *universal.Model[*Polynomial[RE]] {
	//TODO implement me
	panic("implement me")
}

func (r *PolynomialRing[RE]) FromBytes(bytes []byte) (*Polynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (r *PolynomialRing[RE]) ElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (r *PolynomialRing[RE]) Characteristic() crtp.Cardinal {
	//TODO implement me
	panic("implement me")
}

func (r *PolynomialRing[RE]) OpIdentity() *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (r *PolynomialRing[RE]) One() *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (r *PolynomialRing[RE]) Zero() *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (r *PolynomialRing[RE]) IsSemiDomain() bool {
	//TODO implement me
	panic("implement me")
}

func NewPolynomialRing[RE algebra.RingElement[RE]](ring FiniteRing[RE]) (*PolynomialRing[RE], error) {
	r := &PolynomialRing[RE]{
		ring: ring,
	}
	return r, nil
}

type Polynomial[RE algebra.RingElement[RE]] struct {
	coeffs []RE
}

func (p *Polynomial[RE]) Eval(at RE) RE {
	ring := algebra.StructureMustBeAs[algebra.Ring[RE]](at.Structure())
	if len(p.coeffs) == 0 {
		return ring.Zero()
	}
	out := p.coeffs[len(p.coeffs)-1].Clone()
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		out = out.Mul(at).Add(p.coeffs[i])
	}
	return out
}

func (p *Polynomial[RE]) Structure() crtp.Structure[*Polynomial[RE]] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Bytes() []byte {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Clone() *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Equal(rhs *Polynomial[RE]) bool {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) HashCode() base.HashCode {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) String() string {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Op(e *Polynomial[RE]) *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) OtherOp(e *Polynomial[RE]) *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Add(e *Polynomial[RE]) *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Double() *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Mul(e *Polynomial[RE]) *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Square() *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) IsOpIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) TryOpInv() (*Polynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) IsOne() bool {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) TryInv() (*Polynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) TryDiv(e *Polynomial[RE]) (*Polynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) IsZero() bool {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) TryNeg() (*Polynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) TrySub(e *Polynomial[RE]) (*Polynomial[RE], error) {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) OpInv() *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Neg() *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Sub(e *Polynomial[RE]) *Polynomial[RE] {
	//TODO implement me
	panic("implement me")
}

func (p *Polynomial[RE]) Degree() int {
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		if !p.coeffs[i].IsOpIdentity() {
			return i
		}
	}
	return -1
}

func (p *Polynomial[RE]) ConstantTerm() RE {
	return p.coeffs[0]
}
