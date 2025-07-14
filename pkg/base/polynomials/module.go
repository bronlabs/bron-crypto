package polynomials

import (
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/ase/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type (
	PolynomialModule[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]]       algebra.PolynomialModule[ModuleValuedPolynomial[C, S], Polynomial[S], C, S]
	ModuleValuedPolynomial[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]] algebra.ModuleValuedPolynomial[ModuleValuedPolynomial[C, S], Polynomial[S], C, S]
)

func NewPolynomialModule[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]](coeffModule algebra.Module[C, S]) (PolynomialModule[C, S], error) {
	if coeffModule == nil {
		return nil, errs.NewIsNil("coeffModule")
	}
	baseRing, ok := coeffModule.ScalarStructure().(algebra.FiniteRing[S])
	if !ok {
		return nil, errs.NewType("coeff module does not have a ring structure")
	}
	return &polynomialModule[C, S]{
		baseRing:    baseRing,
		coeffModule: coeffModule,
	}, nil
}

func NewModuleValuedPolynomialFromCoefficients[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]](coeffs ...C) (ModuleValuedPolynomial[C, S], error) {
	if len(coeffs) == 0 {
		return nil, errs.NewValue("coefficients cannot be empty")
	}
	baseRing, ok := coeffs[0].Structure().(algebra.FiniteRing[S])
	if !ok {
		return nil, errs.NewType("coefficients do not have a ring structure")
	}
	coeffModule, ok := coeffs[0].Structure().(algebra.Module[C, S])
	if !ok {
		return nil, errs.NewType("coefficients do not have a module structure")
	}
	return &moduleValuedPolynomial[C, S]{
		coeffs:      slices.Clone(coeffs),
		baseRing:    baseRing,
		coeffModule: coeffModule,
	}, nil
}

func LiftToExponent[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]](p Polynomial[S], basepoint C) (ModuleValuedPolynomial[C, S], error) {
	if p == nil {
		return nil, errs.NewIsNil("polynomial p")
	}
	if basepoint.IsOpIdentity() {
		return nil, errs.NewIsZero("basepoint is operation identity")
	}
	coeffModule, ok := basepoint.Structure().(algebra.Module[C, S])
	if !ok {
		return nil, errs.NewType("basepoint does not have a module structure")
	}
	polyModule, err := NewPolynomialModule(coeffModule)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create polynomial module")
	}
	liftedCoeffs := make([]C, len(p.Coefficients()))
	for i, pi := range p.Coefficients() {
		liftedCoeffs[i] = basepoint.ScalarOp(pi)
	}
	return polyModule.New(liftedCoeffs...)
}

type polynomialModule[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]] struct {
	baseRing    algebra.FiniteRing[S]
	coeffModule algebra.Module[C, S]
}

func (m *polynomialModule[C, S]) Name() string {
	return fmt.Sprintf("%s[%s[x]]", m.coeffModule.Name(), m.baseRing.Name())
}

func (m *polynomialModule[C, S]) ElementSize() int {
	return m.coeffModule.ElementSize()
}

func (m *polynomialModule[C, S]) FromBytes(bytes []byte) (ModuleValuedPolynomial[C, S], error) {
	if len(bytes) == 0 {
		return m.OpIdentity(), nil
	}
	if len(bytes)%m.coeffModule.ElementSize() != 0 {
		return nil, errs.NewLength("bytes length must be a multiple of coefficient module element size")
	}

	numCoeffs := len(bytes) / m.coeffModule.ElementSize()
	coeffs := make([]C, numCoeffs)
	for i := range numCoeffs {
		start := i * m.coeffModule.ElementSize()
		end := start + m.coeffModule.ElementSize()
		c, err := m.coeffModule.FromBytes(bytes[start:end])
		if err != nil {
			return nil, errs.WrapSerialisation(err, "failed to deserialize coefficient")
		}
		coeffs[i] = c
	}
	return m.New(coeffs...)
}

func (m *polynomialModule[C, S]) New(coeffs ...C) (ModuleValuedPolynomial[C, S], error) {
	return &moduleValuedPolynomial[C, S]{
		coeffs:      coeffs,
		baseRing:    m.baseRing,
		coeffModule: m.coeffModule,
	}, nil
}

func (m *polynomialModule[C, S]) OpIdentity() ModuleValuedPolynomial[C, S] {
	return &moduleValuedPolynomial[C, S]{
		coeffs:      []C{m.coeffModule.OpIdentity()},
		baseRing:    m.baseRing,
		coeffModule: m.coeffModule,
	}
}

func (m *polynomialModule[C, S]) Order() cardinal.Cardinal {
	return m.coeffModule.Order().Mul(m.baseRing.Order())
}

func (m *polynomialModule[C, S]) ScalarStructure() algebra.Structure[S] {
	return m.baseRing
}

func (m *polynomialModule[C, S]) CoefficientStructure() algebra.Structure[C] {
	return m.coeffModule
}

func (m *polynomialModule[C, S]) MultiScalarOp(scs []S, ps []ModuleValuedPolynomial[C, S]) (ModuleValuedPolynomial[C, S], error) {
	if len(scs) != len(ps) {
		return nil, errs.NewSize("scalar and polynomial slices must have the same length")
	}
	if len(scs) == 0 {
		return nil, errs.NewValue("cannot perform multi-scalar operation on empty slices")
	}

	out := m.OpIdentity()
	for i, pi := range ps {
		out = out.Op(pi.ScalarOp(scs[i]))
	}
	return out, nil
}

func (m *polynomialModule[C, S]) MultiPolynomialOp(ps []Polynomial[S], qs []ModuleValuedPolynomial[C, S]) (ModuleValuedPolynomial[C, S], error) {
	if len(ps) != len(qs) {
		return nil, errs.NewSize("polynomial and module-polynomial slices must have the same length")
	}
	if len(ps) == 0 {
		return nil, errs.NewValue("cannot perform multi-polynomial operation on empty slices")
	}

	out := m.OpIdentity()
	for i, p := range ps {
		out = out.Op(qs[i].PolynomialOp(p))
	}
	return out, nil
}

func (m *polynomialModule[C, S]) Iter() iter.Seq[ModuleValuedPolynomial[C, S]] {
	panic("Iter() is not implemented for polynomial modules")
}

type moduleValuedPolynomial[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]] struct {
	coeffs      []C
	baseRing    algebra.FiniteRing[S]
	coeffModule algebra.Module[C, S]
}

func (p *moduleValuedPolynomial[C, S]) IsConstant() bool {
	return len(p.coeffs) <= 1
}

func (p *moduleValuedPolynomial[C, S]) reduceCoefficients() {
	n := len(p.coeffs)
	for n > 0 && p.coeffs[n-1].IsOpIdentity() {
		n--
	}
	p.coeffs = p.coeffs[:max(n, 1)]
}

func (p *moduleValuedPolynomial[C, S]) Structure() algebra.Structure[ModuleValuedPolynomial[C, S]] {
	return &polynomialModule[C, S]{
		baseRing:    p.baseRing,
		coeffModule: p.coeffModule,
	}
}

func (p *moduleValuedPolynomial[C, S]) Degree() int {
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		if !p.coeffs[i].IsOpIdentity() {
			return i
		}
	}
	return -1
}

func (p *moduleValuedPolynomial[C, S]) Derivative() ModuleValuedPolynomial[C, S] {
	panic("not implemented")
}

func (p *moduleValuedPolynomial[C, S]) ConstantTerm() C {
	if len(p.coeffs) == 0 {
		return p.coeffModule.OpIdentity()
	}
	return p.coeffs[0]
}

func (p *moduleValuedPolynomial[C, S]) ScalarStructure() algebra.Structure[S] {
	return p.baseRing
}

func (p *moduleValuedPolynomial[C, S]) CoefficientStructure() algebra.Structure[C] {
	return p.coeffModule
}

func (p *moduleValuedPolynomial[C, S]) Coefficients() []C {
	return p.coeffs
}

func (p *moduleValuedPolynomial[C, S]) LeadingCoefficient() C {
	p.reduceCoefficients()
	return p.coeffs[len(p.coeffs)-1]
}

func (p *moduleValuedPolynomial[C, S]) IsMonic() bool {
	return p.LeadingCoefficient().IsOpIdentity()
}

func (p *moduleValuedPolynomial[C, S]) Op(q ModuleValuedPolynomial[C, S]) ModuleValuedPolynomial[C, S] {
	if p.Degree() < q.Degree() {
		return q.Op(p)
	}
	out := &moduleValuedPolynomial[C, S]{
		coeffs:      slices.Clone(p.coeffs),
		baseRing:    p.baseRing,
		coeffModule: p.coeffModule,
	}
	for i, qi := range q.Coefficients() {
		out.coeffs[i] = out.coeffs[i].Op(qi)
	}
	out.reduceCoefficients()
	return out
}

func (p *moduleValuedPolynomial[C, S]) IsHomogeneous() bool {
	if len(p.coeffs) == 0 {
		return true // empty polynomial is considered homogeneous
	}
	deg := p.Degree()
	for i, coeff := range p.coeffs {
		if !coeff.IsOpIdentity() && i != deg {
			return false
		}
	}
	return true
}

func (p *moduleValuedPolynomial[C, S]) PolynomialOp(q Polynomial[S]) ModuleValuedPolynomial[C, S] {
	n := len(p.coeffs) + len(q.Coefficients()) - 1
	out := &moduleValuedPolynomial[C, S]{
		coeffs:      make([]C, n),
		baseRing:    p.baseRing,
		coeffModule: p.coeffModule,
	}
	for i := range out.coeffs {
		out.coeffs[i] = p.coeffModule.OpIdentity()
	}
	for i, c := range p.coeffs {
		for j, qj := range q.Coefficients() {
			out.coeffs[i+j] = out.coeffs[i+j].Op(c.ScalarOp(qj))
		}
	}
	out.reduceCoefficients()
	return out
}

func (p *moduleValuedPolynomial[C, S]) Bytes() []byte {
	bs := make([]byte, len(p.coeffs)*p.coeffModule.ElementSize())
	for i, c := range p.coeffs {
		copy(bs[i*p.coeffModule.ElementSize():], c.Bytes())
	}
	return bs
}

func (p *moduleValuedPolynomial[C, S]) ScalarOp(x S) ModuleValuedPolynomial[C, S] {
	out := &moduleValuedPolynomial[C, S]{
		coeffs:      make([]C, len(p.coeffs)),
		baseRing:    p.baseRing,
		coeffModule: p.coeffModule,
	}
	for i, c := range p.coeffs {
		out.coeffs[i] = c.ScalarOp(x)
	}
	out.reduceCoefficients()
	return out
}

func (p *moduleValuedPolynomial[C, S]) TryOpInv() (ModuleValuedPolynomial[C, S], error) {
	return p.OpInv(), nil
}

func (p *moduleValuedPolynomial[C, S]) OpInv() ModuleValuedPolynomial[C, S] {
	out := &moduleValuedPolynomial[C, S]{
		coeffs:      make([]C, len(p.coeffs)),
		baseRing:    p.baseRing,
		coeffModule: p.coeffModule,
	}
	for i := 0; i <= p.Degree(); i++ {
		out.coeffs[i] = p.coeffs[i].OpInv()
	}
	return out
}

func (p *moduleValuedPolynomial[C, S]) Eval(x S) C {
	if len(p.coeffs) == 0 {
		return p.coeffModule.OpIdentity()
	}
	out := p.coeffs[len(p.coeffs)-1].Clone()
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		out = out.ScalarOp(x).Op(p.coeffs[i])
	}
	return out
}

func (p *moduleValuedPolynomial[C, S]) ScalarRing() algebra.FiniteRing[S] {
	return p.baseRing
}

func (p *moduleValuedPolynomial[C, S]) IsOpIdentity() bool {
	return (len(p.coeffs) == 1 && p.coeffs[0].IsOpIdentity())
}

func (p *moduleValuedPolynomial[C, S]) HashCode() base.HashCode {
	return base.HashCode((p.Degree())) ^ p.coeffs[0].HashCode()
}

func (p *moduleValuedPolynomial[C, S]) Equal(q ModuleValuedPolynomial[C, S]) bool {
	for i := range max(len(p.coeffs), len(q.Coefficients())) {
		pi := p.coeffModule.OpIdentity()
		if i < len(p.coeffs) {
			pi = p.coeffs[i]
		}
		qi := p.coeffModule.OpIdentity()
		if i < len(q.Coefficients()) {
			qi = q.Coefficients()[i]
		}
		if !pi.Equal(qi) {
			return false
		}
	}
	return true
}

func (p *moduleValuedPolynomial[C, S]) IsTorsionFree() bool {
	for i := range p.coeffs {
		if !p.coeffs[i].IsTorsionFree() {
			return false
		}
	}
	return true
}

func (p *moduleValuedPolynomial[C, S]) String() string {
	// TODO: handle negative coefficients
	if len(p.coeffs) == 0 || p.IsOpIdentity() {
		return "0"
	}

	terms := []string{}
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		coeff := p.coeffs[i]
		if coeff.IsOpIdentity() {
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

func (p *moduleValuedPolynomial[C, S]) Clone() ModuleValuedPolynomial[C, S] {
	return &moduleValuedPolynomial[C, S]{
		coeffs:      slices.Clone(p.coeffs),
		baseRing:    p.baseRing,
		coeffModule: p.coeffModule,
	}
}

func _[C algebra.ModuleElement[C, S], S algebra.RingElement[S]]() {
	var _ PolynomialModule[C, S] = &polynomialModule[C, S]{}
	var _ ModuleValuedPolynomial[C, S] = &moduleValuedPolynomial[C, S]{}
}
