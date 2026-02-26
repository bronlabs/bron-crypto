package polynomials

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/errs-go/errs"
)

// LiftPolynomial lifts a scalar polynomial into a module-valued polynomial by
// multiplying each coefficient by the base module element.
func LiftPolynomial[ME algebra.ModuleElement[ME, RE], RE algebra.RingElement[RE]](poly *Polynomial[RE], baseElem algebra.ModuleElement[ME, RE]) (*ModuleValuedPolynomial[ME, RE], error) {
	coeffs := make([]ME, len(poly.coeffs))
	for i, c := range poly.coeffs {
		coeffs[i] = baseElem.ScalarOp(c)
	}

	p := &ModuleValuedPolynomial[ME, RE]{
		coeffs: coeffs,
	}
	return p, nil
}

// PolynomialModule is the module M[x] of univariate polynomials whose
// coefficients live in a finite module M. Scalars come from the scalar ring
// of M. It implements algebra.Module[*ModuleValuedPolynomial[ME, S], S].
type PolynomialModule[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	module algebra.FiniteModule[ME, S]
}

// NewPolynomialModule constructs a polynomial module over the given finite module.
func NewPolynomialModule[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]](module algebra.FiniteModule[ME, S]) (*PolynomialModule[ME, S], error) {
	if module == nil {
		return nil, ErrValidation.WithMessage("nil module")
	}
	return &PolynomialModule[ME, S]{module: module}, nil
}

// New creates a module-valued polynomial from the given coefficients in
// ascending degree order. If no coefficients are given the zero polynomial
// is returned.
func (m *PolynomialModule[ME, S]) New(coeffs ...ME) (*ModuleValuedPolynomial[ME, S], error) {
	if len(coeffs) < 1 {
		return m.OpIdentity(), nil
	}
	for _, c := range coeffs {
		if utils.IsNil(c) {
			return nil, ErrValidation.WithStackFrame()
		}
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}, nil
}

// Name returns a human-readable name of the form "PolynomialModule[M, S]".
func (m *PolynomialModule[ME, S]) Name() string {
	return fmt.Sprintf("PolynomialModule[%s, %s]", m.module.Name(), m.module.ScalarStructure().Name())
}

// RandomModuleValuedPolynomial returns a random module-valued polynomial of
// the given degree with a random constant term.
func (m *PolynomialModule[ME, S]) RandomModuleValuedPolynomial(degree int, prng io.Reader) (*ModuleValuedPolynomial[ME, S], error) {
	if degree < 0 {
		return nil, ErrValidation.WithMessage("negative degree")
	}
	finiteModule := algebra.StructureMustBeAs[algebra.FiniteModule[ME, S]](m.module)
	constantTerm, err := finiteModule.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample random constant term")
	}
	poly, err := m.RandomModuleValuedPolynomialWithConstantTerm(degree, constantTerm, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create random polynomial with constant term")
	}
	return poly, nil
}

// RandomModuleValuedPolynomialWithConstantTerm returns a random module-valued
// polynomial of the given degree whose constant coefficient equals
// constantTerm. The leading coefficient is guaranteed to be non-identity.
func (m *PolynomialModule[ME, S]) RandomModuleValuedPolynomialWithConstantTerm(degree int, constantTerm ME, prng io.Reader) (*ModuleValuedPolynomial[ME, S], error) {
	if degree < 0 {
		return nil, ErrValidation.WithMessage("negative degree")
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
			return nil, errs.Wrap(err).WithMessage("failed to sample random coefficient")
		}
	}
	leading, err := algebrautils.RandomNonIdentity(finiteModule, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample random leading coefficient")
	}
	coeffs[degree] = leading

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}, nil
}

// Order returns Infinite, since a polynomial module has infinitely many elements.
func (*PolynomialModule[ME, S]) Order() algebra.Cardinal {
	return cardinal.Infinite()
}

// FromBytes deserialises a module-valued polynomial from a concatenation of
// fixed-size coefficient encodings in ascending degree order.
func (m *PolynomialModule[ME, S]) FromBytes(bytes []byte) (*ModuleValuedPolynomial[ME, S], error) {
	coeffSize := m.module.ElementSize()
	if len(bytes) == 0 {
		return m.OpIdentity(), nil
	}
	if (len(bytes) % coeffSize) != 0 {
		return nil, ErrValidation.WithMessage("invalid input length")
	}

	numCoeffs := len(bytes) / coeffSize
	coeffs := make([]ME, numCoeffs)
	for i := range numCoeffs {
		start := i * coeffSize
		end := start + coeffSize
		c, err := m.module.FromBytes(bytes[start:end])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to deserialize coefficient")
		}
		coeffs[i] = c
	}
	poly, err := m.New(coeffs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create polynomial from deserialized coefficients")
	}
	return poly, nil
}

// ElementSize returns -1 because module-valued polynomials are variable-length.
func (*PolynomialModule[ME, S]) ElementSize() int {
	return -1
}

// OpIdentity returns the additive identity (zero module-valued polynomial).
func (m *PolynomialModule[ME, S]) OpIdentity() *ModuleValuedPolynomial[ME, S] {
	return &ModuleValuedPolynomial[ME, S]{coeffs: []ME{m.module.OpIdentity()}}
}

// ScalarStructure returns the scalar ring of the underlying module.
func (m *PolynomialModule[ME, S]) ScalarStructure() algebra.Structure[S] {
	return m.module.ScalarStructure()
}

// CoefficientStructure returns the underlying coefficient module.
func (m *PolynomialModule[ME, S]) CoefficientStructure() algebra.Structure[ME] {
	return m.module
}

// ModuleValuedPolynomial is a univariate polynomial whose coefficients are
// elements of a module ME over a scalar ring S, stored in ascending degree
// order. It implements algebra.ModuleElement[*ModuleValuedPolynomial[ME, S], S].
type ModuleValuedPolynomial[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	coeffs []ME
}

// Structure reconstructs the parent PolynomialModule from the coefficient module.
func (p *ModuleValuedPolynomial[ME, S]) Structure() algebra.Structure[*ModuleValuedPolynomial[ME, S]] {
	if len(p.coeffs) == 0 {
		panic("internal error: empty coeffs")
	}

	module := algebra.StructureMustBeAs[algebra.FiniteModule[ME, S]](p.coeffs[0].Structure())
	return &PolynomialModule[ME, S]{
		module: module,
	}
}

// CoefficientStructure returns the finite module that the coefficients belong to.
func (p *ModuleValuedPolynomial[ME, S]) CoefficientStructure() algebra.FiniteModule[ME, S] {
	if len(p.coeffs) == 0 {
		panic("internal error: empty coeffs")
	}
	return algebra.StructureMustBeAs[algebra.FiniteModule[ME, S]](p.coeffs[0].Structure())
}

// ScalarStructure returns the scalar ring of the coefficient module.
func (p *ModuleValuedPolynomial[ME, S]) ScalarStructure() algebra.Ring[S] {
	return algebra.StructureMustBeAs[algebra.Ring[S]](p.CoefficientStructure().ScalarStructure())
}

// ConstantTerm returns the degree-0 coefficient.
func (p *ModuleValuedPolynomial[ME, S]) ConstantTerm() ME {
	return p.coeffs[0]
}

// IsConstant reports whether the polynomial has degree 0 or less.
func (p *ModuleValuedPolynomial[ME, S]) IsConstant() bool {
	return p.Degree() <= 0
}

// LeadingCoefficient returns the highest-degree non-identity coefficient, or
// the module identity if p is the zero polynomial.
func (p *ModuleValuedPolynomial[ME, S]) LeadingCoefficient() ME {
	deg := p.Degree()
	if deg < 0 {
		return p.CoefficientStructure().OpIdentity()
	}
	return p.coeffs[deg]
}

// PolynomialOp multiplies a module-valued polynomial by a scalar polynomial
// via convolution (schoolbook multiplication using ScalarOp for coefficient
// scaling and Op for coefficient addition).
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

// Derivative returns the formal derivative p'(x).
func (p *ModuleValuedPolynomial[ME, S]) Derivative() *ModuleValuedPolynomial[ME, S] {
	if len(p.coeffs) <= 1 {
		return &ModuleValuedPolynomial[ME, S]{
			coeffs: []ME{p.CoefficientStructure().OpIdentity()},
		}
	}
	ring := algebra.StructureMustBeAs[algebra.FiniteRing[S]](p.ScalarStructure())
	derivCoeffs := make([]ME, len(p.coeffs)-1)
	for i := 1; i < len(p.coeffs); i++ {
		// Create properly sized big-endian bytes for the index
		elemSize := ring.ElementSize()
		indexBytes := make([]byte, elemSize)
		binary.BigEndian.PutUint64(indexBytes[elemSize-8:], uint64(i))
		rb, err := ring.FromBytes(indexBytes)
		if err != nil {
			panic("internal error: could not create ring element from uint64")
		}
		derivCoeffs[i-1] = p.coeffs[i].ScalarOp(rb)
	}
	return &ModuleValuedPolynomial[ME, S]{
		coeffs: derivCoeffs,
	}
}

// Bytes serialises the polynomial as a concatenation of coefficient bytes in
// ascending degree order.
func (p *ModuleValuedPolynomial[ME, S]) Bytes() []byte {
	out := make([]byte, 0, len(p.coeffs)*p.CoefficientStructure().ElementSize())
	for _, c := range p.coeffs {
		out = append(out, c.Bytes()...)
	}
	return out
}

// Clone returns a deep copy of the polynomial.
func (p *ModuleValuedPolynomial[ME, S]) Clone() *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i, c := range p.coeffs {
		coeffs[i] = c.Clone()
	}
	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

// Equal reports whether p and rhs represent the same polynomial (trailing
// identity coefficients are ignored).
func (p *ModuleValuedPolynomial[ME, S]) Equal(rhs *ModuleValuedPolynomial[ME, S]) bool {
	for i := range min(len(p.coeffs), len(rhs.coeffs)) {
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

// HashCode returns a hash derived from XOR-ing the hash codes of all coefficients.
func (p *ModuleValuedPolynomial[ME, S]) HashCode() base.HashCode {
	h := base.HashCode(0)
	for _, c := range p.coeffs {
		h ^= c.HashCode()
	}
	return h
}

// String returns a bracket-delimited list of coefficient strings.
func (p *ModuleValuedPolynomial[ME, S]) String() string {
	repr := "["
	for _, c := range p.coeffs {
		repr += fmt.Sprintf("%s, ", c.String())
	}
	repr += "]"
	return repr
}

// Op returns the sum of two module-valued polynomials (coefficient-wise addition).
func (p *ModuleValuedPolynomial[ME, S]) Op(e *ModuleValuedPolynomial[ME, S]) *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, max(len(p.coeffs), len(e.coeffs)))
	for i := range min(len(p.coeffs), len(e.coeffs)) {
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

// OpElement adds a module element to the constant term of p.
func (p *ModuleValuedPolynomial[ME, S]) OpElement(e ME) *ModuleValuedPolynomial[ME, S] {
	clone := p.Clone()
	clone.coeffs[0] = clone.coeffs[0].Op(e)
	return clone
}

// IsOpIdentity reports whether all coefficients are the module identity.
func (p *ModuleValuedPolynomial[ME, S]) IsOpIdentity() bool {
	for _, c := range p.coeffs {
		if !c.IsOpIdentity() {
			return false
		}
	}
	return true
}

// TryOpInv returns the additive inverse of p (always succeeds).
func (p *ModuleValuedPolynomial[ME, S]) TryOpInv() (*ModuleValuedPolynomial[ME, S], error) {
	return p.OpInv(), nil
}

// OpInv returns the additive inverse of p (coefficient-wise inversion).
func (p *ModuleValuedPolynomial[ME, S]) OpInv() *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i, c := range p.coeffs {
		coeffs[i] = c.OpInv()
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

// ScalarOp multiplies every coefficient by the scalar (module action).
func (p *ModuleValuedPolynomial[ME, S]) ScalarOp(actor S) *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i := 0; i < len(coeffs); i++ {
		coeffs[i] = p.coeffs[i].ScalarOp(actor)
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

// IsTorsionFree reports whether every coefficient is torsion-free.
func (p *ModuleValuedPolynomial[ME, S]) IsTorsionFree() bool {
	for i := range p.coeffs {
		if !p.coeffs[i].IsTorsionFree() {
			return false
		}
	}
	return true
}

// Eval evaluates the module-valued polynomial at the given scalar point using
// Horner's method.
func (p *ModuleValuedPolynomial[ME, S]) Eval(at S) ME {
	out := p.coeffs[len(p.coeffs)-1].Clone()
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		out = out.ScalarOp(at).Op(p.coeffs[i])
	}
	return out
}

// Degree returns the degree of p (the index of the highest non-identity
// coefficient), or −1 for the zero polynomial.
func (p *ModuleValuedPolynomial[ME, S]) Degree() int {
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		if !p.coeffs[i].IsOpIdentity() {
			return i
		}
	}
	return -1
}

// Coefficients returns the coefficient slice in ascending degree order.
func (p *ModuleValuedPolynomial[ME, S]) Coefficients() []ME {
	return p.coeffs
}
