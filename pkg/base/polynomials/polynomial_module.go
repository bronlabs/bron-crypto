package polynomials

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// interface compliance
func _[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]]() {
	var (
		_ algebra.Module[*ModuleValuedPolynomial[ME, S], S]        = (*PolynomialModule[ME, S])(nil)
		_ algebra.ModuleElement[*ModuleValuedPolynomial[ME, S], S] = (*ModuleValuedPolynomial[ME, S])(nil)
	)
}

type PolynomialModule[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	module algebra.Module[ME, S]
}

func (m *PolynomialModule[ME, S]) New(coeffs ...ME) *ModuleValuedPolynomial[ME, S] {
	if len(coeffs) < 1 {
		return m.OpIdentity()
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (m *PolynomialModule[ME, S]) Name() string {
	return fmt.Sprintf("PolynomialModule[%s, %s]", m.module.Name(), m.module.ScalarStructure().Name())
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
	return m.New(coeffs...), nil
}

func (m *PolynomialModule[ME, S]) ElementSize() int {
	panic("internal error: not supported")
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

type moduleValuedPolynomialDTO[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	Coeffs []ME `cbor:"coefficients"`
}

func (p *ModuleValuedPolynomial[ME, S]) Structure() algebra.Structure[*ModuleValuedPolynomial[ME, S]] {
	if len(p.coeffs) == 0 {
		panic("internal error: empty coeffs")
	}

	module := algebra.StructureMustBeAs[algebra.Module[ME, S]](p.coeffs[0].Structure())
	return &PolynomialModule[ME, S]{
		module: module,
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

func (p *ModuleValuedPolynomial[ME, S]) Coefficients() []ME {
	return p.coeffs
}

func (p *ModuleValuedPolynomial[ME, S]) MarshalCBOR() ([]byte, error) {
	dto := &moduleValuedPolynomialDTO[ME, S]{
		Coeffs: p.coeffs,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal polynomial")
	}
	return data, nil
}

func (p *ModuleValuedPolynomial[ME, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*moduleValuedPolynomialDTO[ME, S]](data)
	if err != nil {
		return err
	}
	p.coeffs = dto.Coeffs
	return nil
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
