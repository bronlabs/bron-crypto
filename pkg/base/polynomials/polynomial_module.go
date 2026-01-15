package polynomials

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

// interface compliance
func _[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]]() {
	var (
		_ algebra.Module[*ModuleValuedPolynomial[ME, S], S]        = (*PolynomialModule[ME, S])(nil)
		_ algebra.ModuleElement[*ModuleValuedPolynomial[ME, S], S] = (*ModuleValuedPolynomial[ME, S])(nil)
	)
}

func LiftPolynomial[ME algebra.ModuleElement[ME, RE], RE algebra.RingElement[RE]](poly *Polynomial[RE], base algebra.ModuleElement[ME, RE]) (*ModuleValuedPolynomial[ME, RE], error) {
	coeffs := make([]ME, len(poly.coeffs))
	for i, c := range poly.coeffs {
		coeffs[i] = base.ScalarOp(c)
	}

	p := &ModuleValuedPolynomial[ME, RE]{
		coeffs: coeffs,
	}
	return p, nil
}

type PolynomialModule[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	module algebra.FiniteModule[ME, S]
}

func NewPolynomialModule[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]](module algebra.FiniteModule[ME, S]) *PolynomialModule[ME, S] {
	return &PolynomialModule[ME, S]{module: module}
}

func (m *PolynomialModule[ME, S]) New(coeffs ...ME) (*ModuleValuedPolynomial[ME, S], error) {
	if len(coeffs) < 1 {
		return m.OpIdentity(), nil
	}
	for _, c := range coeffs {
		if utils.IsNil(c) {
			return nil, errs.NewIsNil("coefficient cannot be nil")
		}
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}, nil
}

func (m *PolynomialModule[ME, S]) Name() string {
	return fmt.Sprintf("PolynomialModule[%s, %s]", m.module.Name(), m.module.ScalarStructure().Name())
}

func (m *PolynomialModule[ME, S]) RandomModuleValuedPolynomial(degree int, prng io.Reader) (*ModuleValuedPolynomial[ME, S], error) {
	if degree < 0 {
		return nil, errs.NewFailed("degree cannot be negative")
	}
	finiteModule := algebra.StructureMustBeAs[algebra.FiniteModule[ME, S]](m.module)
	constantTerm, err := finiteModule.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample random constant term")
	}
	poly, err := m.RandomModuleValuedPolynomialWithConstantTerm(degree, constantTerm, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create random polynomial with constant term")
	}
	return poly, nil
}

func (m *PolynomialModule[ME, S]) RandomModuleValuedPolynomialWithConstantTerm(degree int, constantTerm ME, prng io.Reader) (*ModuleValuedPolynomial[ME, S], error) {
	if degree < 0 {
		return nil, errs.NewFailed("degree cannot be negative")
	}

	finiteModule := algebra.StructureMustBeAs[algebra.FiniteModule[ME, S]](m.module)
	coeffs := make([]ME, degree+1)
	coeffs[0] = constantTerm.Clone()
	if degree == 0 {
		return &ModuleValuedPolynomial[ME, S]{coeffs: coeffs}, nil
	}
	for i := 1; i < degree; i++ {
		var err error
		coeffs[i], err = finiteModule.Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "failed to sample random coefficient")
		}
	}
	leading, err := algebrautils.RandomNonIdentity(finiteModule, prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample random leading coefficient")
	}
	coeffs[degree] = leading

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}, nil
}

func (m *PolynomialModule[ME, S]) Order() algebra.Cardinal {
	return cardinal.Infinite()
}

func (m *PolynomialModule[ME, S]) FromBytes(bytes []byte) (*ModuleValuedPolynomial[ME, S], error) {
	coeffSize := m.module.ElementSize()
	if len(bytes) == 0 {
		return m.OpIdentity(), nil
	}
	if (len(bytes) % coeffSize) != 0 {
		return nil, errs.NewLength("bytes length must be a multiple of coefficient module element size")
	}

	numCoeffs := len(bytes) / coeffSize
	coeffs := make([]ME, numCoeffs)
	for i := range numCoeffs {
		start := i * coeffSize
		end := start + coeffSize
		c, err := m.module.FromBytes(bytes[start:end])
		if err != nil {
			return nil, errs.WrapSerialisation(err, "failed to deserialize coefficient")
		}
		coeffs[i] = c
	}
	poly, err := m.New(coeffs...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create polynomial from deserialized coefficients")
	}
	return poly, nil
}

func (m *PolynomialModule[ME, S]) ElementSize() int {
	return -1
}

func (m *PolynomialModule[ME, S]) OpIdentity() *ModuleValuedPolynomial[ME, S] {
	return &ModuleValuedPolynomial[ME, S]{coeffs: []ME{m.module.OpIdentity()}}
}

func (m *PolynomialModule[ME, S]) ScalarStructure() algebra.Structure[S] {
	return m.module.ScalarStructure()
}

func (m *PolynomialModule[ME, S]) MultiScalarOp(scalars []S, elements []*ModuleValuedPolynomial[ME, S]) (*ModuleValuedPolynomial[ME, S], error) {
	if len(scalars) != len(elements) {
		return nil, errs.NewSize("scalar and polynomial slices must have the same length")
	}
	if len(scalars) == 0 {
		return nil, errs.NewValue("cannot perform multi-scalar operation on empty slices")
	}

	out := m.OpIdentity()
	for i, pi := range elements {
		out = out.Op(pi.ScalarOp(scalars[i]))
	}
	return out, nil
}

type ModuleValuedPolynomial[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	coeffs []ME
}

func (p *ModuleValuedPolynomial[ME, S]) Structure() algebra.Structure[*ModuleValuedPolynomial[ME, S]] {
	if len(p.coeffs) == 0 {
		panic("internal error: empty coeffs")
	}

	module := algebra.StructureMustBeAs[algebra.FiniteModule[ME, S]](p.coeffs[0].Structure())
	return &PolynomialModule[ME, S]{
		module: module,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) CoefficientStructure() algebra.FiniteModule[ME, S] {
	if len(p.coeffs) == 0 {
		panic("internal error: empty coeffs")
	}
	return algebra.StructureMustBeAs[algebra.FiniteModule[ME, S]](p.coeffs[0].Structure())
}

func (p *ModuleValuedPolynomial[ME, S]) ScalarStructure() algebra.Ring[S] {
	return algebra.StructureMustBeAs[algebra.Ring[S]](p.CoefficientStructure().ScalarStructure())
}

func (p *ModuleValuedPolynomial[ME, S]) ConstantTerm() ME {
	return p.coeffs[0]
}

func (p *ModuleValuedPolynomial[ME, S]) IsConstant() bool {
	return p.Degree() <= 0
}

func (p *ModuleValuedPolynomial[ME, S]) LeadingCoefficient() ME {
	deg := p.Degree()
	if deg < 0 {
		return p.CoefficientStructure().OpIdentity()
	}
	return p.coeffs[deg]
}

func (p *ModuleValuedPolynomial[ME, S]) PolynomialOp(poly *Polynomial[S]) *ModuleValuedPolynomial[ME, S] {
	if len(p.coeffs) == 0 || len(poly.coeffs) == 0 {
		return p.Clone()
	}
	module := p.CoefficientStructure()
	coeffs := make([]ME, len(p.coeffs)+len(poly.coeffs)-1)
	for i := range coeffs {
		coeffs[i] = module.OpIdentity()
	}
	for i := range p.coeffs {
		for j := range poly.coeffs {
			coeffs[i+j] = coeffs[i+j].Op(p.coeffs[i].ScalarOp(poly.coeffs[j]))
		}
	}
	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) Derivative() *ModuleValuedPolynomial[ME, S] {
	if len(p.coeffs) <= 1 {
		return &ModuleValuedPolynomial[ME, S]{
			coeffs: []ME{p.CoefficientStructure().OpIdentity()},
		}
	}
	ring := p.ScalarStructure()
	derivCoeffs := make([]ME, len(p.coeffs)-1)
	for i := 1; i < len(p.coeffs); i++ {
		rb, err := ring.FromBytes(binary.BigEndian.AppendUint64(nil, uint64(i)))
		if err != nil {
			panic("internal error: could not create ring element from uint64")
		}
		derivCoeffs[i-1] = p.coeffs[i].ScalarOp(rb)
	}
	return &ModuleValuedPolynomial[ME, S]{
		coeffs: derivCoeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) Bytes() []byte {
	var out []byte
	for _, c := range p.coeffs {
		out = append(out, c.Bytes()...)
	}
	return out
}

func (p *ModuleValuedPolynomial[ME, S]) Clone() *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i, c := range p.coeffs {
		coeffs[i] = c.Clone()
	}
	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) Equal(rhs *ModuleValuedPolynomial[ME, S]) bool {
	for i := 0; i < min(len(p.coeffs), len(rhs.coeffs)); i++ {
		if !p.coeffs[i].Equal(rhs.coeffs[i]) {
			return false
		}
	}
	for i := len(p.coeffs); i < max(len(p.coeffs), len(rhs.coeffs)); i++ {
		if !rhs.coeffs[i].IsOpIdentity() {
			return false
		}
	}
	for i := len(rhs.coeffs); i < max(len(p.coeffs), len(rhs.coeffs)); i++ {
		if !p.coeffs[i].IsOpIdentity() {
			return false
		}
	}

	return true
}

func (p *ModuleValuedPolynomial[ME, S]) HashCode() base.HashCode {
	h := base.HashCode(0)
	for _, c := range p.coeffs {
		h ^= c.HashCode()
	}
	return h
}

func (p *ModuleValuedPolynomial[ME, S]) String() string {
	repr := "["
	for _, c := range p.coeffs {
		repr += fmt.Sprintf("%s, ", c.String())
	}
	repr += "]"
	return repr
}

func (p *ModuleValuedPolynomial[ME, S]) Op(e *ModuleValuedPolynomial[ME, S]) *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, max(len(p.coeffs), len(e.coeffs)))
	for i := 0; i < min(len(p.coeffs), len(e.coeffs)); i++ {
		coeffs[i] = p.coeffs[i].Op(e.coeffs[i])
	}
	for i := len(p.coeffs); i < max(len(p.coeffs), len(e.coeffs)); i++ {
		coeffs[i] = e.coeffs[i].Clone()
	}
	for i := len(e.coeffs); i < max(len(p.coeffs), len(e.coeffs)); i++ {
		coeffs[i] = p.coeffs[i].Clone()
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) OpElement(e ME) *ModuleValuedPolynomial[ME, S] {
	clone := p.Clone()
	clone.coeffs[0] = clone.coeffs[0].Op(e)
	return clone
}

func (p *ModuleValuedPolynomial[ME, S]) IsOpIdentity() bool {
	for _, c := range p.coeffs {
		if !c.IsOpIdentity() {
			return false
		}
	}
	return true
}

func (p *ModuleValuedPolynomial[ME, S]) TryOpInv() (*ModuleValuedPolynomial[ME, S], error) {
	return p.OpInv(), nil
}

func (p *ModuleValuedPolynomial[ME, S]) OpInv() *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i, c := range p.coeffs {
		coeffs[i] = c.OpInv()
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) ScalarOp(actor S) *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i := 0; i < len(coeffs); i++ {
		coeffs[i] = p.coeffs[i].ScalarOp(actor)
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) IsTorsionFree() bool {
	for i := range p.coeffs {
		if !p.coeffs[i].IsTorsionFree() {
			return false
		}
	}
	return true
}

func (p *ModuleValuedPolynomial[ME, S]) Eval(at S) ME {
	out := p.coeffs[len(p.coeffs)-1].Clone()
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		out = out.ScalarOp(at).Op(p.coeffs[i])
	}
	return out
}

func (p *ModuleValuedPolynomial[ME, S]) Degree() int {
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		if !p.coeffs[i].IsOpIdentity() {
			return i
		}
	}
	return -1
}

func (p *ModuleValuedPolynomial[ME, S]) Coefficients() []ME {
	return p.coeffs
}
