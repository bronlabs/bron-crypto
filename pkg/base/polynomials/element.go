package polynomials

import (
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

type UnivariatePolynomial[InnerField algebra.AbstractFiniteField[InnerField, InnerFieldElement], InnerFieldElement algebra.AbstractFiniteFieldElement[InnerField, InnerFieldElement]] struct {
	// coefficients invariant: coefficients[len(coefficients) - 1].IsAdditiveIdentity iff (len(coefficients) == 1) and coefficients[0].IsAdditiveIdentity()
	set          *UnivariatePolynomialsSet[InnerField, InnerFieldElement]
	coefficients []InnerFieldElement
}

// Univariate Polynomial Trait implementation.

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Eval(at InnerFieldElement) InnerFieldElement {
	y := e.set.InnerField().AdditiveIdentity()
	for i := range e.coefficients {
		y = y.Mul(at).Add(e.coefficients[len(e.coefficients)-1-i])
	}
	return y
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Degree() int {
	if e.IsAdditiveIdentity() {
		return -1
	} else {
		return len(e.coefficients) - 1
	}
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Coefficients() []InnerFieldElement {
	return e.coefficients
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) EuclideanDiv(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) (quo, rem *UnivariatePolynomial[InnerField, InnerFieldElement]) {
	a := e.Clone()
	b := rhs.Clone()
	q := e.set.AdditiveIdentity()
	r := a
	d := b.Degree()
	c := b.leadingCoefficient()
	for r.Degree() >= d {
		sCoeffs := make([]InnerFieldElement, r.Degree()-d+1)
		for i := range sCoeffs {
			sCoeffs[i] = e.set.innerField.AdditiveIdentity()
		}
		sCoeffs[r.Degree()-d] = r.leadingCoefficient().Div(c)
		s := e.set.NewUnivariatePolynomial(sCoeffs)
		q = q.Add(s)
		r = r.Sub(s.Mul(b))
	}
	return q, r
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Derivative() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	coefficients := make([]InnerFieldElement, len(e.coefficients)-1)
	for i := 1; i < len(e.coefficients); i++ {
		coefficients[i-1] = e.coefficients[i].ApplyAdd(e.coefficients[i], new(saferith.Nat).SetUint64(uint64(i-1)))
	}

	return &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: coefficients,
	}
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) EuclideanGcd(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	a := e
	b := rhs
	for !b.IsAdditiveIdentity() {
		_, c := a.EuclideanDiv(b)
		a = b
		b = c
	}

	return a
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) EuclideanLcm(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	gcd := e.EuclideanGcd(rhs)
	rhsOverGcd, _ := rhs.EuclideanDiv(gcd)
	return e.Mul(rhsOverGcd)
}

// Abstract Ring Element implementation.

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Equal(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) bool {
	if len(e.coefficients) != len(rhs.coefficients) {
		return false
	}
	for i, c := range e.coefficients {
		if !c.Equal(rhs.coefficients[i]) {
			return false
		}
	}

	return true
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Clone() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	clone := &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: make([]InnerFieldElement, len(e.coefficients)),
	}
	for i, c := range e.coefficients {
		clone.coefficients[i] = c.Clone()
	}
	return clone
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(e.coefficients)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot serialise polynomial")
	}

	return data, nil
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Add(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	degree := utils.Max(len(e.coefficients), len(rhs.coefficients))
	coefficients := make([]InnerFieldElement, degree)
	for i := range coefficients {
		switch {
		case i < len(e.coefficients) && i < len(rhs.coefficients):
			coefficients[i] = e.coefficients[i].Add(rhs.coefficients[i])
		case i < len(e.coefficients):
			coefficients[i] = e.coefficients[i]
		default: // i < len(rhs.coefficients)
			coefficients[i] = rhs.coefficients[i]
		}
	}

	result := &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: coefficients,
	}
	result.normalise()
	return result
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) ApplyAdd(x *UnivariatePolynomial[InnerField, InnerFieldElement], n *saferith.Nat) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	y := e.Clone()
	isLess := func(x, y *saferith.Nat) bool {
		_, _, less := x.Cmp(y)
		return less != 0
	}
	for i := new(saferith.Nat).SetUint64(0); isLess(i, n); i = utils.Saferith.NatIncrement(i) {
		y = y.Add(x)
	}

	return y
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Double() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	double := &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: make([]InnerFieldElement, len(e.coefficients)),
	}
	for i, c := range e.coefficients {
		e.coefficients[i] = c.Double()
	}
	return double
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Triple() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	triple := &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: make([]InnerFieldElement, len(e.coefficients)),
	}
	for i, c := range e.coefficients {
		e.coefficients[i] = c.Triple()
	}
	return triple
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) IsAdditiveIdentity() bool {
	return len(e.coefficients) == 1 && e.coefficients[0].IsAdditiveIdentity()
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) AdditiveInverse() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	inverse := &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: make([]InnerFieldElement, len(e.coefficients)),
	}
	for i, c := range e.coefficients {
		e.coefficients[i] = c.AdditiveInverse()
	}
	return inverse
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) IsAdditiveInverse(of *UnivariatePolynomial[InnerField, InnerFieldElement]) bool {
	if len(e.coefficients) != len(of.coefficients) {
		return false
	}

	for i, c := range e.coefficients {
		if !c.IsAdditiveInverse(of.coefficients[i]) {
			return false
		}
	}

	return true
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Neg() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	coefficients := make([]InnerFieldElement, len(e.coefficients))
	for i, c := range e.coefficients {
		coefficients[i] = c.Neg()
	}

	return &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: coefficients,
	}
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Sub(x *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	degree := utils.Max(len(e.coefficients), len(x.coefficients))
	coefficients := make([]InnerFieldElement, degree)
	for i := range coefficients {
		switch {
		case i < len(e.coefficients) && i < len(x.coefficients):
			coefficients[i] = e.coefficients[i].Sub(x.coefficients[i])
		case i < len(e.coefficients):
			coefficients[i] = e.coefficients[i]
		default: // i < len(rhs.coefficients)
			coefficients[i] = x.coefficients[i].Neg()
		}
	}

	result := &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: coefficients,
	}
	result.normalise()
	return result
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) ApplySub(x *UnivariatePolynomial[InnerField, InnerFieldElement], n *saferith.Nat) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	y := e.Clone()
	isLess := func(x, y *saferith.Nat) bool {
		_, _, less := x.Cmp(y)
		return less != 0
	}
	for i := new(saferith.Nat).SetUint64(0); isLess(i, n); i = utils.Saferith.NatIncrement(i) {
		y = y.Sub(x)
	}

	return y
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Mul(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	degree := len(e.coefficients) + len(rhs.coefficients) - 1
	coefficients := make([]InnerFieldElement, degree)
	for i := range coefficients {
		coefficients[i] = e.set.innerField.AdditiveIdentity()
	}
	for i, l := range e.coefficients {
		for j, r := range rhs.coefficients {
			coefficients[i+j] = coefficients[i+j].Add(l.Mul(r))
		}
	}

	result := &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: coefficients,
	}
	result.normalise()
	return result
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) ApplyMul(x *UnivariatePolynomial[InnerField, InnerFieldElement], n *saferith.Nat) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	y := e.Clone()
	isLess := func(x, y *saferith.Nat) bool {
		_, _, less := x.Cmp(y)
		return less != 0
	}
	for i := new(saferith.Nat).SetUint64(0); isLess(i, n); i = utils.Saferith.NatIncrement(i) {
		y = y.Mul(x)
	}

	return y
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Square() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return e.Mul(e)
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Cube() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return e.Square().Mul(e)
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) IsMultiplicativeIdentity() bool {
	return len(e.coefficients) == 1 && e.coefficients[0].IsMultiplicativeIdentity()
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) MulAdd(p, q *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return e.Mul(p).Add(q)
}

func (*UnivariatePolynomial[InnerField, InnerFieldElement]) Sqrt() (*UnivariatePolynomial[InnerField, InnerFieldElement], error) {
	return nil, errs.NewFailed("not supported")
}

func (*UnivariatePolynomial[InnerField, InnerFieldElement]) Uint64() uint64 {
	panic("not supported")
}

func (*UnivariatePolynomial[InnerField, InnerFieldElement]) SetNat(v *saferith.Nat) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	panic("not supported")
}

func (*UnivariatePolynomial[InnerField, InnerFieldElement]) Nat() *saferith.Nat {
	panic("not supported")
}

// Algebra vector implementation.

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Operate(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return e.Add(rhs)
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) OperateIteratively(rhs *UnivariatePolynomial[InnerField, InnerFieldElement], n *saferith.Nat) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return e.ApplyAdd(rhs, n)
}

func (*UnivariatePolynomial[InnerField, InnerFieldElement]) Order() *saferith.Modulus {
	panic("not supported")
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) IsIdentity() bool {
	return e.IsAdditiveIdentity()
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Inverse() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return e.AdditiveInverse()
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) IsInverse(of *UnivariatePolynomial[InnerField, InnerFieldElement]) bool {
	return e.IsAdditiveInverse(of)
}

func (*UnivariatePolynomial[InnerField, InnerFieldElement]) IsTorsionElement(order *saferith.Modulus) bool {
	panic("not supported")
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) ScalarMul(rhs InnerFieldElement) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	coefficients := make([]InnerFieldElement, len(e.coefficients))
	for i, c := range e.coefficients {
		coefficients[i] = c.Mul(rhs)
	}

	return &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          e.set,
		coefficients: coefficients,
	}
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) Prod(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return e.Mul(rhs)
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) normalise() {
	truncate := 0
	for i := 0; i < len(e.coefficients)-1; i++ {
		if !e.coefficients[len(e.coefficients)-1-i].IsAdditiveIdentity() {
			break
		}
		truncate++
	}
	e.coefficients = e.coefficients[:len(e.coefficients)-truncate]
}

func (e *UnivariatePolynomial[InnerField, InnerFieldElement]) leadingCoefficient() InnerFieldElement {
	return e.coefficients[len(e.coefficients)-1]
}
