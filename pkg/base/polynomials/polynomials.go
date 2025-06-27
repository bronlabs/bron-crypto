package polynomials

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type (
	PolynomialRing[S algebra.FiniteRingElement[S]] algebra.PolynomialRing[Polynomial[S], S]
	Polynomial[S algebra.FiniteRingElement[S]]     algebra.Polynomial[Polynomial[S], S]
)

func NewPolynomialRing[S algebra.FiniteRingElement[S]](coeffRing algebra.FiniteRing[S]) (PolynomialRing[S], error) {
	if coeffRing == nil {
		return nil, errs.NewIsNil("coeffRing")
	}
	return &polynomialRing[S]{coeffRing: coeffRing}, nil
}

func NewPolynomialFromCoefficients[S algebra.FiniteRingElement[S]](coeffs ...S) (Polynomial[S], error) {
	if len(coeffs) == 0 {
		return nil, errs.NewSize("coefficients must not be empty")
	}
	coeffRing, ok := coeffs[0].Structure().(algebra.FiniteRing[S])
	if !ok {
		return nil, errs.NewArgument("first coefficient must be a finite ring element")
	}
	return &coefficientForm[S]{
		coeffs:    coeffs,
		coeffRing: coeffRing,
	}, nil
}

type polynomialRing[S algebra.RingElement[S]] struct {
	coeffRing algebra.FiniteRing[S]
}

func (r *polynomialRing[S]) Name() string {
	return fmt.Sprintf("%s[x]", r.coeffRing.Name())
}

func (r *polynomialRing[S]) ElementSize() int {
	return r.coeffRing.ElementSize()
}

func (r *polynomialRing[S]) Characteristic() cardinal.Cardinal {
	return r.coeffRing.Characteristic()
}

func (r *polynomialRing[S]) New(coeffs ...S) (Polynomial[S], error) {
	return &coefficientForm[S]{
		coeffs:    coeffs,
		coeffRing: r.coeffRing,
	}, nil
}

func (r *polynomialRing[S]) IsDomain() bool {
	return r.coeffRing.IsDomain()
}

func (r *polynomialRing[S]) FromBytes(inBytes []byte) (Polynomial[S], error) {
	if len(inBytes) == 0 {
		return nil, errs.NewSize("input bytes must not be empty")
	}
	size := r.ElementSize()
	if len(inBytes)%size != 0 {
		return nil, errs.NewSize("input bytes length must be a multiple of element size")
	}
	numCoeffs := len(inBytes) / size
	coeffs := make([]S, numCoeffs)
	for i := 0; i < numCoeffs; i++ {
		start := i * size
		end := start + size
		var err error
		coeffs[i], err = r.coeffRing.FromBytes(inBytes[start:end])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not parse coefficient")
		}
	}
	return r.New(coeffs...)
}

func (r *polynomialRing[S]) RandomPolynomialWithConstantTerm(degree int, constantTerm S, prng io.Reader) (Polynomial[S], error) {
	if degree < -1 {
		return nil, errs.NewSize("degree must be greater than or equal to -1")
	}
	if degree == -1 {
		return r.Zero(), nil
	}
	if degree == 0 {
		return &coefficientForm[S]{
			coeffs:    []S{constantTerm},
			coeffRing: r.coeffRing,
		}, nil
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	p := &coefficientForm[S]{
		coeffs:    make([]S, degree+1),
		coeffRing: r.coeffRing,
	}
	p.coeffs[0] = constantTerm.Clone()
	for i := 1; i < int(degree)+1; i++ {
		var err error
		p.coeffs[i], err = r.coeffRing.Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not sample field element")
		}
	}
	return p, nil
}

func (r *polynomialRing[S]) RandomPolynomial(degree int, prng io.Reader) (Polynomial[S], error) {
	if degree < -1 {
		return nil, errs.NewSize("degree must be greater than or equal to -1")
	}
	if degree == -1 {
		return r.Zero(), nil
	}
	constantTerm, err := r.coeffRing.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not sample ring element")
	}
	return r.RandomPolynomialWithConstantTerm(degree, constantTerm, prng)
}

func (r *polynomialRing[S]) MultiScalarOp(scs []S, ps []Polynomial[S]) (Polynomial[S], error) {
	return r.MultiScalarMul(scs, ps)
}

func (r *polynomialRing[S]) MultiScalarMul(scs []S, ps []Polynomial[S]) (Polynomial[S], error) {
	if len(scs) != len(ps) {
		return nil, errs.NewSize("length of scalars and polynomials must match")
	}
	if len(scs) == 0 {
		return r.Zero(), nil
	}
	out, _ := r.New()
	for i, s := range scs {
		out = out.Add(ps[i].ScalarMul(s))
	}
	return out, nil
}

func (r *polynomialRing[S]) Order() cardinal.Cardinal {
	return cardinal.Infinite
}

func (r *polynomialRing[S]) OpIdentity() Polynomial[S] {
	res, _ := r.New(r.coeffRing.OpIdentity())
	return res
}

func (r *polynomialRing[S]) Zero() Polynomial[S] {
	res, _ := r.New(r.coeffRing.Zero())
	return res
}

func (r *polynomialRing[S]) One() Polynomial[S] {
	res, _ := r.New(r.coeffRing.One())
	return res
}
func (r *polynomialRing[S]) ScalarStructure() algebra.Structure[S] {
	return r.coeffRing
}

func (r *polynomialRing[S]) CoefficientStructure() algebra.Structure[S] {
	return r.coeffRing
}

type coefficientForm[S algebra.RingElement[S]] struct {
	coeffs    []S
	coeffRing algebra.FiniteRing[S]
}

func (r *coefficientForm[S]) ScalarStructure() algebra.Structure[S] {
	return r.coeffRing
}

func (r *coefficientForm[S]) CoefficientStructure() algebra.Structure[S] {
	return r.coeffRing
}

func (p *coefficientForm[S]) Degree() int {
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		if !p.coeffs[i].IsZero() {
			return i
		}
	}
	return -1
}

func (p *coefficientForm[S]) IsHomogeneous() bool {
	if len(p.coeffs) == 0 {
		return true // empty polynomial is considered homogeneous
	}
	deg := p.Degree()
	for i, coeff := range p.coeffs {
		if !coeff.IsZero() && i != deg {
			return false
		}
	}
	return true
}

func (p *coefficientForm[S]) reduceCoefficients() {
	n := len(p.coeffs)
	for n > 0 && p.coeffs[n-1].IsZero() {
		n--
	}
	p.coeffs = p.coeffs[:max(n, 1)] // if all coefficients are zero, keep one zero coefficient
}

func (p *coefficientForm[S]) Coefficients() []S {
	return p.coeffs
}

func (p *coefficientForm[S]) Bytes() []byte {
	size := p.coeffRing.ElementSize()
	out := make([]byte, 0, size*len(p.coeffs))
	for _, coeff := range p.coeffs {
		out = append(out, coeff.Bytes()...)
	}
	return out
}

func (p *coefficientForm[S]) Derivative() Polynomial[S] {
	if len(p.coeffs) <= 1 {
		return &coefficientForm[S]{
			coeffs:    []S{p.coeffRing.Zero()},
			coeffRing: p.coeffRing,
		}
	}

	out := &coefficientForm[S]{
		coeffs:    make([]S, len(p.coeffs)-1),
		coeffRing: p.coeffRing,
	}

	one := p.coeffRing.One()

	for i := 1; i < len(p.coeffs); i++ {
		scalar := one.Clone()
		for j := 1; j < i; j++ {
			scalar = scalar.Add(one)
		}
		out.coeffs[i-1] = p.coeffs[i].Mul(scalar)
	}

	out.reduceCoefficients()
	return out
}

func (p *coefficientForm[S]) Eval(x S) S {
	if len(p.coeffs) == 0 {
		return p.coeffRing.Zero()
	}
	out := p.coeffs[len(p.coeffs)-1].Clone()
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		out = out.Mul(x).Add(p.coeffs[i])
	}
	return out
}

func (p *coefficientForm[S]) CoefficientRing() algebra.FiniteRing[S] {
	return p.coeffRing
}

func (p *coefficientForm[S]) ConstantTerm() S {
	if len(p.coeffs) == 0 {
		return p.coeffRing.Zero()
	}
	return p.coeffs[0]
}

func (p *coefficientForm[S]) LeadingCoefficient() S {
	p.reduceCoefficients()
	return p.coeffs[len(p.coeffs)-1]
}

func (p *coefficientForm[S]) IsConstant() bool {
	return len(p.coeffs) <= 1
}

func (p *coefficientForm[S]) IsMonic() bool {
	return p.LeadingCoefficient().IsOne()
}

func (p *coefficientForm[S]) Structure() algebra.Structure[Polynomial[S]] {
	return &polynomialRing[S]{
		coeffRing: p.coeffRing,
	}
}

func (p *coefficientForm[S]) Op(q Polynomial[S]) Polynomial[S] {
	return p.Add(q)
}

func (p *coefficientForm[S]) OtherOp(q Polynomial[S]) Polynomial[S] {
	return p.Mul(q)
}

func (p *coefficientForm[S]) Add(q Polynomial[S]) Polynomial[S] {
	if p.Degree() < q.Degree() {
		return q.Add(p)
	}
	out := &coefficientForm[S]{
		coeffs:    slices.Clone(p.coeffs),
		coeffRing: p.coeffRing,
	}
	for i, qi := range q.Coefficients() {
		out.coeffs[i] = out.coeffs[i].Add(qi)
	}
	out.reduceCoefficients()
	return out
}

func (p *coefficientForm[S]) TrySub(q Polynomial[S]) (Polynomial[S], error) {
	return p.Sub(q), nil
}

func (p *coefficientForm[S]) Sub(q Polynomial[S]) Polynomial[S] {
	// Handle the case where q has more coefficients than p
	maxLen := max(len(p.coeffs), len(q.Coefficients()))
	out := &coefficientForm[S]{
		coeffs:    make([]S, maxLen),
		coeffRing: p.coeffRing,
	}

	// Copy p's coefficients
	for i, pi := range p.coeffs {
		out.coeffs[i] = pi.Clone()
	}

	// Fill remaining with zeros if q has more coefficients
	for i := len(p.coeffs); i < maxLen; i++ {
		out.coeffs[i] = p.coeffRing.Zero()
	}

	// Subtract q's coefficients
	for i, qi := range q.Coefficients() {
		out.coeffs[i] = out.coeffs[i].Sub(qi)
	}

	out.reduceCoefficients()
	return out
}

func (p *coefficientForm[S]) Double() Polynomial[S] {
	out := &coefficientForm[S]{
		coeffs:    make([]S, len(p.coeffs)),
		coeffRing: p.coeffRing,
	}
	for i, c := range p.coeffs {
		out.coeffs[i] = c.Double()
	}
	return out
}

func (p *coefficientForm[S]) TryOpInv() (Polynomial[S], error) {
	return p.OpInv(), nil
}

func (p *coefficientForm[S]) OpInv() Polynomial[S] {
	return p.Neg()
}

func (p *coefficientForm[S]) TryNeg() (Polynomial[S], error) {
	return p.Neg(), nil
}

func (p *coefficientForm[S]) Neg() Polynomial[S] {
	out := &coefficientForm[S]{
		coeffs:    make([]S, len(p.coeffs)),
		coeffRing: p.coeffRing,
	}
	for i, c := range p.coeffs {
		out.coeffs[i] = c.Neg()
	}
	return out
}

func (p *coefficientForm[S]) Mul(q Polynomial[S]) Polynomial[S] {
	n := len(p.coeffs) + len(q.Coefficients()) - 1
	out := &coefficientForm[S]{
		coeffs:    make([]S, n),
		coeffRing: p.coeffRing,
	}
	for i := range out.coeffs {
		out.coeffs[i] = p.coeffRing.Zero()
	}
	for i, c := range p.coeffs {
		for j, qj := range q.Coefficients() {
			out.coeffs[i+j] = out.coeffs[i+j].Add(c.Mul(qj))
		}
	}
	out.reduceCoefficients()
	return out
}

func (p *coefficientForm[S]) Square() Polynomial[S] {
	return p.Mul(p)
}

func (p *coefficientForm[S]) ScalarOp(s S) Polynomial[S] {
	return p.ScalarMul(s)
}

func (p *coefficientForm[S]) ScalarMul(s S) Polynomial[S] {
	out := &coefficientForm[S]{
		coeffs:    make([]S, len(p.coeffs)),
		coeffRing: p.coeffRing,
	}
	for i, c := range p.coeffs {
		out.coeffs[i] = c.Mul(s)
	}
	out.reduceCoefficients()
	return out
}

func (p *coefficientForm[S]) ScalarExp(s S) Polynomial[S] {
	// TODO: add binary methods to scalar or similar
	panic("not implemented")
}

func (p *coefficientForm[S]) IsOpIdentity() bool {
	return p.IsZero()
}

func (p *coefficientForm[S]) IsZero() bool {
	return (len(p.coeffs) == 1 && p.coeffs[0].IsZero())
}

func (p *coefficientForm[S]) IsOne() bool {
	return len(p.coeffs) == 1 && p.coeffs[0].IsOne()
}

func (p *coefficientForm[S]) TryDiv(q Polynomial[S]) (Polynomial[S], error) {
	quot, rem, err := p.EuclideanDiv(q)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not divide polynomial")
	}
	if !rem.IsZero() {
		return nil, errs.NewFailed("polynomial division not exact")
	}
	return quot, nil
}

func (p *coefficientForm[S]) TryInv() (Polynomial[S], error) {
	if p.Degree() != 0 {
		return nil, errs.NewValue("polynomial inverse only defined for constants")
	}
	inv, err := p.coeffs[0].TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "coefficient not invertible")
	}
	return &coefficientForm[S]{
		coeffs:    []S{inv},
		coeffRing: p.coeffRing,
	}, nil
}
func (p *coefficientForm[S]) EuclideanDiv(q Polynomial[S]) (Polynomial[S], Polynomial[S], error) {
	if q.Degree() == -1 {
		return nil, nil, errs.NewIsZero("division by zero polynomial")
	}

	dividend := p.Clone().(*coefficientForm[S])
	divisor := q.(*coefficientForm[S])
	degDiff := dividend.Degree() - divisor.Degree()

	if degDiff < 0 {
		zero := p.coeffRing.Zero()
		return &coefficientForm[S]{coeffs: []S{zero}, coeffRing: p.coeffRing}, dividend, nil
	}

	quotient := make([]S, degDiff+1)
	remainder := make([]S, len(dividend.coeffs))
	for i := range dividend.coeffs {
		remainder[i] = dividend.coeffs[i].Clone()
	}

	lc := divisor.LeadingCoefficient()
	invLC, err := lc.TryInv()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "divisor leading coefficient not invertible")
	}

	for i := len(remainder) - 1; i >= divisor.Degree(); i-- {
		coeff := remainder[i].Mul(invLC)
		quotient[i-divisor.Degree()] = coeff
		for j := 0; j <= divisor.Degree(); j++ {
			remainder[i-divisor.Degree()+j] = remainder[i-divisor.Degree()+j].Sub(coeff.Mul(divisor.coeffs[j]))
		}
	}

	qPoly := &coefficientForm[S]{coeffs: quotient, coeffRing: p.coeffRing}
	rPoly := &coefficientForm[S]{coeffs: remainder, coeffRing: p.coeffRing}
	qPoly.reduceCoefficients()
	rPoly.reduceCoefficients()
	return qPoly, rPoly, nil
}

func (p *coefficientForm[S]) IsProbablyPrime() bool {
	panic("not implemented")
}

func (p *coefficientForm[S]) IsTorsionFree() bool {
	// TODO: add IsDomain function
	return true
}

func (p *coefficientForm[S]) Equal(q Polynomial[S]) bool {
	for i := range max(len(p.coeffs), len(q.Coefficients())) {
		pi := p.coeffRing.Zero()
		if i < len(p.coeffs) {
			pi = p.coeffs[i]
		}
		qi := q.CoefficientStructure().(algebra.FiniteRing[S]).Zero()
		if i < len(q.Coefficients()) {
			qi = q.Coefficients()[i]
		}
		if !pi.Equal(qi) {
			return false
		}
	}
	return true
}

func (p *coefficientForm[S]) HashCode() base.HashCode {
	return base.HashCode(p.Degree()) ^ p.coeffs[0].HashCode()
}

func (p *coefficientForm[S]) Clone() Polynomial[S] {
	out := &coefficientForm[S]{
		coeffs:    make([]S, len(p.coeffs)),
		coeffRing: p.coeffRing,
	}
	for i, c := range p.coeffs {
		out.coeffs[i] = c.Clone()
	}
	return out
}

func (p *coefficientForm[S]) String() string {
	// TODO: handle negative coefficients
	if len(p.coeffs) == 0 || p.IsZero() {
		return "0"
	}

	terms := []string{}
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		coeff := p.coeffs[i]
		if coeff.IsZero() {
			continue
		}

		var term string
		switch i {
		case 0:
			term = fmt.Sprintf("%s", coeff)
		case 1:
			term = fmt.Sprintf("%s*x", coeff)
		default:
			term = fmt.Sprintf("%s*x^%d", coeff, i)
		}

		terms = append(terms, term)
	}

	return strings.Join(terms, " + ")
}

func _[S algebra.RingElement[S]]() {
	var _ Polynomial[S] = (*coefficientForm[S])(nil)
	var _ PolynomialRing[S] = (*polynomialRing[S])(nil)
}
