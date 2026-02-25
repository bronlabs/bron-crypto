package polynomials

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/errs-go/errs"
)

type PolynomialRing[RE algebra.RingElement[RE]] struct {
	ring algebra.FiniteRing[RE]
}

func (r *PolynomialRing[RE]) RandomPolynomial(degree int, prng io.Reader) (*Polynomial[RE], error) {
	constantTerm, err := r.ring.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample random constant term")
	}
	poly, err := r.RandomPolynomialWithConstantTerm(degree, constantTerm, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create random polynomial with constant term")
	}
	return poly, nil
}

func (r *PolynomialRing[RE]) RandomPolynomialWithConstantTerm(degree int, constantTerm RE, prng io.Reader) (*Polynomial[RE], error) {
	if degree < 0 {
		return nil, ErrValidation.WithMessage("degree is negative")
	}

	var err error
	coeffs := make([]RE, degree+1)
	coeffs[0] = constantTerm.Clone()
	for i := 1; i < degree; i++ {
		coeffs[i], err = r.ring.Random(prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to sample random coefficient")
		}
	}
	coeffs[degree], err = algebrautils.RandomNonIdentity(r.ring, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample random leading coefficient")
	}
	p := &Polynomial[RE]{
		coeffs: coeffs,
	}
	return p, nil
}

func (r *PolynomialRing[RE]) New(coeffs ...RE) (*Polynomial[RE], error) {
	if len(coeffs) == 0 {
		coeffs = []RE{r.ring.Zero()}
	}
	for _, c := range coeffs {
		if utils.IsNil(c) {
			return nil, ErrValidation.WithStackFrame()
		}
	}

	return &Polynomial[RE]{
		coeffs: coeffs,
	}, nil
}

func (r *PolynomialRing[RE]) Name() string {
	return fmt.Sprintf("PolynomialRing[%s]", r.ring.Name())
}

func (*PolynomialRing[RE]) Order() algebra.Cardinal {
	return cardinal.Infinite()
}

func (r *PolynomialRing[RE]) FromBytes(inBytes []byte) (*Polynomial[RE], error) {
	if len(inBytes) == 0 {
		return nil, ErrValidation.WithMessage("empty input")
	}

	coeffSize := r.ring.ElementSize()
	if len(inBytes)%coeffSize != 0 {
		return nil, ErrValidation.WithMessage("invalid input length")
	}
	numCoeffs := len(inBytes) / coeffSize
	coeffs := make([]RE, numCoeffs)
	for i := range numCoeffs {
		start := i * coeffSize
		end := start + coeffSize
		var err error
		coeffs[i], err = r.ring.FromBytes(inBytes[start:end])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not parse coefficient")
		}
	}
	poly, err := r.New(coeffs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create polynomial")
	}
	return poly, nil
}

func (*PolynomialRing[RE]) ElementSize() int {
	return -1
}

func (r *PolynomialRing[RE]) Characteristic() algebra.Cardinal {
	return r.ring.Characteristic()
}

func (r *PolynomialRing[RE]) OpIdentity() *Polynomial[RE] {
	return r.Zero()
}

func (r *PolynomialRing[RE]) One() *Polynomial[RE] {
	return &Polynomial[RE]{
		coeffs: []RE{r.ring.One()},
	}
}

func (r *PolynomialRing[RE]) Zero() *Polynomial[RE] {
	return &Polynomial[RE]{
		coeffs: []RE{r.ring.Zero()},
	}
}

func (r *PolynomialRing[RE]) IsDomain() bool {
	return r.ring.IsDomain()
}

func (r *PolynomialRing[RE]) ScalarStructure() algebra.Structure[RE] {
	return r.ring
}

func NewPolynomialRing[RE algebra.RingElement[RE]](ring algebra.FiniteRing[RE]) (*PolynomialRing[RE], error) {
	r := &PolynomialRing[RE]{
		ring: ring,
	}
	return r, nil
}

type Polynomial[RE algebra.RingElement[RE]] struct {
	coeffs []RE
}

func (p *Polynomial[RE]) Coefficients() []RE {
	return p.coeffs
}

func (p *Polynomial[RE]) CoefficientStructure() algebra.Ring[RE] {
	if len(p.coeffs) == 0 {
		panic("internal error: empty coeffs")
	}
	return algebra.StructureMustBeAs[algebra.Ring[RE]](p.coeffs[0].Structure())
}

func (p *Polynomial[RE]) Eval(at RE) RE {
	ring := algebra.StructureMustBeAs[algebra.FiniteRing[RE]](at.Structure())
	// although we always require a polynomial to have at least one coefficient (even if it's zero), we do not panic here
	if len(p.coeffs) == 0 {
		return ring.Zero()
	}

	out := p.coeffs[len(p.coeffs)-1].Clone()
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		out = out.Mul(at).Add(p.coeffs[i])
	}
	return out
}

func (p *Polynomial[RE]) Structure() algebra.Structure[*Polynomial[RE]] {
	if len(p.coeffs) == 0 {
		panic("internal error: empty coeffs")
	}

	underlyingRing := algebra.StructureMustBeAs[algebra.FiniteRing[RE]](p.coeffs[0].Structure())
	return &PolynomialRing[RE]{
		ring: underlyingRing,
	}
}

func (p *Polynomial[RE]) Bytes() []byte {
	out := make([]byte, 0, len(p.coeffs)*p.CoefficientStructure().ElementSize())
	for _, coeff := range p.coeffs {
		out = append(out, coeff.Bytes()...)
	}
	return out
}

func (p *Polynomial[RE]) Clone() *Polynomial[RE] {
	clone := &Polynomial[RE]{
		coeffs: make([]RE, len(p.coeffs)),
	}
	for i, c := range p.coeffs {
		clone.coeffs[i] = c.Clone()
	}
	return clone
}

func (p *Polynomial[RE]) Equal(rhs *Polynomial[RE]) bool {
	for i := range min(len(p.coeffs), len(rhs.coeffs)) {
		if !p.coeffs[i].Equal(rhs.coeffs[i]) {
			return false
		}
	}
	for i := len(p.coeffs); i < max(len(p.coeffs), len(rhs.coeffs)); i++ {
		if !rhs.coeffs[i].IsZero() {
			return false
		}
	}
	for i := len(rhs.coeffs); i < max(len(p.coeffs), len(rhs.coeffs)); i++ {
		if !p.coeffs[i].IsZero() {
			return false
		}
	}

	return true
}

func (p *Polynomial[RE]) HashCode() base.HashCode {
	h := base.HashCode(0)
	for _, c := range p.coeffs {
		h ^= c.HashCode()
	}
	return h
}

func (p *Polynomial[RE]) String() string {
	repr := "["
	for _, c := range p.coeffs {
		repr += fmt.Sprintf("%s, ", c.String())
	}
	repr += "]"
	return repr
}

func (p *Polynomial[RE]) Op(e *Polynomial[RE]) *Polynomial[RE] {
	return p.Add(e)
}

func (p *Polynomial[RE]) OtherOp(e *Polynomial[RE]) *Polynomial[RE] {
	return p.Mul(e)
}

func (p *Polynomial[RE]) Add(e *Polynomial[RE]) *Polynomial[RE] {
	coeffs := make([]RE, max(len(p.coeffs), len(e.coeffs)))
	for i := range min(len(p.coeffs), len(e.coeffs)) {
		coeffs[i] = p.coeffs[i].Add(e.coeffs[i])
	}
	for i := len(p.coeffs); i < max(len(p.coeffs), len(e.coeffs)); i++ {
		coeffs[i] = e.coeffs[i].Clone()
	}
	for i := len(e.coeffs); i < max(len(p.coeffs), len(e.coeffs)); i++ {
		coeffs[i] = p.coeffs[i].Clone()
	}
	return &Polynomial[RE]{
		coeffs: coeffs,
	}
}

func (p *Polynomial[RE]) Double() *Polynomial[RE] {
	return p.Add(p)
}

func (p *Polynomial[RE]) Mul(e *Polynomial[RE]) *Polynomial[RE] {
	ring := algebra.StructureMustBeAs[algebra.FiniteRing[RE]](p.coeffs[0].Structure())
	coeffs := make([]RE, len(p.coeffs)+len(e.coeffs)-1)
	for i := range coeffs {
		coeffs[i] = ring.Zero()
	}

	for l := range len(p.coeffs) {
		for r := range len(e.coeffs) {
			coeffs[l+r] = coeffs[l+r].Add(p.coeffs[l].Mul(e.coeffs[r]))
		}
	}
	return &Polynomial[RE]{
		coeffs: coeffs,
	}
}

func (p *Polynomial[RE]) Square() *Polynomial[RE] {
	return p.Mul(p)
}

func (p *Polynomial[RE]) IsOpIdentity() bool {
	return p.IsZero()
}

func (p *Polynomial[RE]) TryOpInv() (*Polynomial[RE], error) {
	return p.Neg(), nil
}

func (p *Polynomial[RE]) IsOne() bool {
	if len(p.coeffs) < 1 {
		return false
	}
	for i := len(p.coeffs) - 1; i >= 1; i-- {
		if !p.coeffs[i].IsZero() {
			return false
		}
	}
	return p.coeffs[0].IsOne()
}

func (*Polynomial[RE]) TryInv() (*Polynomial[RE], error) {
	return nil, ErrOperationNotSupported.WithStackFrame()
}

func (*Polynomial[RE]) TryDiv(e *Polynomial[RE]) (*Polynomial[RE], error) {
	return nil, ErrOperationNotSupported.WithStackFrame()
}

func (p *Polynomial[RE]) IsZero() bool {
	if len(p.coeffs) == 0 {
		return true
	}
	for _, c := range p.coeffs {
		if !c.IsZero() {
			return false
		}
	}

	return true
}

func (p *Polynomial[RE]) TryNeg() (*Polynomial[RE], error) {
	return p.Neg(), nil
}

func (p *Polynomial[RE]) TrySub(e *Polynomial[RE]) (*Polynomial[RE], error) {
	return p.Sub(e), nil
}

func (p *Polynomial[RE]) OpInv() *Polynomial[RE] {
	return p.Neg()
}

func (p *Polynomial[RE]) Neg() *Polynomial[RE] {
	coeffs := make([]RE, len(p.coeffs))
	for i, c := range p.coeffs {
		coeffs[i] = c.Neg()
	}
	return &Polynomial[RE]{
		coeffs: coeffs,
	}
}

func (p *Polynomial[RE]) Sub(e *Polynomial[RE]) *Polynomial[RE] {
	return p.Add(e.Neg())
}

func (p *Polynomial[RE]) Degree() int {
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		if !p.coeffs[i].IsZero() {
			return i
		}
	}
	return -1
}

func (p *Polynomial[RE]) ConstantTerm() RE {
	return p.coeffs[0]
}

func (p *Polynomial[RE]) Derivative() *Polynomial[RE] {
	ring := algebra.StructureMustBeAs[algebra.FiniteRing[RE]](p.coeffs[0].Structure())
	if p.Degree() <= 0 {
		return &Polynomial[RE]{
			coeffs: []RE{ring.Zero()},
		}
	}
	derivCoeffs := make([]RE, p.Degree())
	for i := 1; i <= p.Degree(); i++ {
		derivCoeffs[i-1] = algebrautils.ScalarMulUint64(p.coeffs[i], uint64(i))
	}
	return &Polynomial[RE]{
		coeffs: derivCoeffs,
	}
}

func (p *Polynomial[RE]) EuclideanDiv(q *Polynomial[RE]) (quot, rem *Polynomial[RE], err error) {
	coeffField, err := algebra.StructureAs[crtp.Field[RE]](p.coeffs[0].Structure())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("coefficients ring is not a field")
	}
	if q.IsZero() {
		return nil, nil, ErrDivisionByZero.WithStackFrame()
	}
	if p.IsZero() {
		zero := coeffField.Zero()
		return &Polynomial[RE]{coeffs: []RE{zero}}, &Polynomial[RE]{coeffs: []RE{zero.Clone()}}, nil
	}

	rem = p.Clone()
	degQ := q.Degree()
	degR := rem.Degree()
	if degR < degQ {
		return &Polynomial[RE]{coeffs: []RE{coeffField.Zero()}}, rem, nil
	}

	quotCoeffs := make([]RE, degR-degQ+1)
	for i := range quotCoeffs {
		quotCoeffs[i] = coeffField.Zero()
	}

	lcQ := q.coeffs[degQ]
	for degR >= degQ {
		lcR := rem.coeffs[degR]
		factor, err := lcR.TryDiv(lcQ)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("failed to divide leading coefficients")
		}

		shift := degR - degQ
		quotCoeffs[shift] = factor

		for i := 0; i <= degQ; i++ {
			rem.coeffs[i+shift] = rem.coeffs[i+shift].Sub(q.coeffs[i].Mul(factor))
		}

		for degR >= 0 && rem.coeffs[degR].IsZero() {
			degR--
		}
	}

	if degR < 0 {
		rem = &Polynomial[RE]{coeffs: []RE{coeffField.Zero()}}
	} else {
		rem = &Polynomial[RE]{coeffs: rem.coeffs[:degR+1]}
	}

	quot = &Polynomial[RE]{coeffs: quotCoeffs}
	for len(quot.coeffs) > 1 && quot.coeffs[len(quot.coeffs)-1].IsZero() {
		quot.coeffs = quot.coeffs[:len(quot.coeffs)-1]
	}

	return quot, rem, nil
}

func (p *Polynomial[RE]) EuclideanValuation() algebra.Cardinal {
	deg := p.Degree()
	if deg <= 0 {
		return cardinal.New(0)
	}
	return cardinal.New(uint64(deg))
}

func (p *Polynomial[RE]) IsConstant() bool {
	return p.Degree() == 0
}

func (p *Polynomial[RE]) IsMonic() bool {
	deg := p.Degree()
	return deg >= 0 && p.coeffs[deg].IsOne()
}

func (p *Polynomial[RE]) LeadingCoefficient() RE {
	deg := p.Degree()
	if deg < 0 {
		return p.CoefficientStructure().Zero()
	}
	return p.coeffs[deg]
}

func (p *Polynomial[RE]) ScalarOp(s RE) *Polynomial[RE] {
	return p.ScalarMul(s)
}

func (p *Polynomial[RE]) ScalarMul(s RE) *Polynomial[RE] {
	coeffs := make([]RE, len(p.coeffs))
	for i, c := range p.coeffs {
		coeffs[i] = c.Mul(s)
	}
	return &Polynomial[RE]{
		coeffs: coeffs,
	}
}

func (p *Polynomial[RE]) IsTorsionFree() bool {
	_, err := algebra.StructureAs[crtp.Field[RE]](p.coeffs[0].Structure())
	return err == nil
}

func (p *Polynomial[RE]) ScalarStructure() algebra.Ring[RE] {
	return p.CoefficientStructure()
}
