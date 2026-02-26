package polynomials

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions/traits"
	"github.com/bronlabs/errs-go/errs"
)

// LiftDirectSumOfPolynomialsToExponent lifts a direct sum of scalar polynomials
// into a direct sum of module-valued polynomials by lifting each component with
// the corresponding base point.
func LiftDirectSumOfPolynomialsToExponent[C algebra.ModuleElement[C, S], S algebra.RingElement[S]](dsum *DirectSumOfPolynomials[S], basePoints ...C) (*DirectSumOfModuleValuedPolynomials[C, S], error) {
	if dsum == nil {
		return nil, ErrValidation.WithMessage("dsum is nil")
	}
	if len(dsum.Components()) == 0 {
		return nil, ErrValidation.WithMessage("dsum must not be empty")
	}
	if len(basePoints) == 0 {
		return nil, ErrValidation.WithMessage("base points must not be empty")
	}
	coefficientModule, err := algebra.StructureAs[algebra.FiniteModule[C, S]](basePoints[0].Structure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("base point is not a module element")
	}
	polyModule, err := NewPolynomialModule(coefficientModule)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create polynomial module")
	}
	dsumOfModules, err := NewDirectSumOfPolynomialModules(polyModule, uint(dsum.Arity().Uint64()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create direct sum of polynomial modules")
	}
	out, err := dsumOfModules.Lift(dsum.Components(), basePoints...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not lift direct sum of polynomials to exponent")
	}
	return out, nil
}

// NewDirectSumOfPolynomialRings constructs a direct sum of the given polynomial
// ring with the specified arity (number of components).
func NewDirectSumOfPolynomialRings[S algebra.RingElement[S]](polyRing *PolynomialRing[S], arity uint) (*DirectSumOfPolynomialRings[S], error) {
	if arity == 0 {
		return nil, ErrValidation.WithMessage("arity must be greater than 0")
	}
	out := &DirectSumOfPolynomialRings[S]{}
	if err := out.Set(polyRing, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not set direct sum of polynomial rings")
	}
	var _ algebra.Module[*DirectSumOfPolynomials[S], S] = out
	return out, nil
}

// DirectSumOfPolynomialRings is the direct sum of polynomial rings, viewed as
// a module over the scalar ring S. It implements
// algebra.Module[*DirectSumOfPolynomials[S], S].
type DirectSumOfPolynomialRings[S algebra.RingElement[S]] struct {
	traits.DirectSumModule[*PolynomialRing[S], *Polynomial[S], S, *DirectSumOfPolynomials[S], DirectSumOfPolynomials[S]]
}

// CoefficientAlgebra returns the direct sum of regular algebras formed from
// the coefficient ring.
func (r *DirectSumOfPolynomialRings[S]) CoefficientAlgebra() *constructions.DirectSumModule[
	*constructions.FiniteRegularAlgebra[
		algebra.FiniteRing[S],
		S,
	],
	*constructions.FiniteRegularAlgebraElement[S],
	S,
] {
	coeffRing := algebra.StructureMustBeAs[algebra.FiniteRing[S]](r.Factor().ScalarStructure())
	alg, _ := constructions.NewFiniteRegularAlgebra(coeffRing)
	out, _ := constructions.NewDirectSumModule(alg, uint(r.Arity().Uint64()))
	return out
}

// DirectSumOfPolynomials is an element of [DirectSumOfPolynomialRings]:
// a fixed-length tuple of scalar polynomials.
type DirectSumOfPolynomials[S algebra.RingElement[S]] struct {
	traits.DirectSumModuleElement[*Polynomial[S], S, *DirectSumOfPolynomials[S], DirectSumOfPolynomials[S]]
}

// Structure reconstructs the parent DirectSumOfPolynomialRings from the
// first component.
func (p *DirectSumOfPolynomials[S]) Structure() algebra.Structure[*DirectSumOfPolynomials[S]] {
	arity := p.Arity()
	if arity.IsZero() {
		return nil
	}
	polyRing, ok := p.Components()[0].Structure().(*PolynomialRing[S])
	if !ok {
		panic(ErrValidation.WithMessage("component is not a polynomial ring"))
	}
	out, _ := NewDirectSumOfPolynomialRings(polyRing, uint(arity.Uint64()))
	return out
}

// IsDomain always returns false; a direct sum of rings is never a domain.
func (*DirectSumOfPolynomials[S]) IsDomain() bool {
	return false
}

// CoefficientAlgebra returns the direct sum of regular algebras formed from
// the coefficient ring of the first component.
func (p *DirectSumOfPolynomials[S]) CoefficientAlgebra() *constructions.DirectSumModule[
	*constructions.FiniteRegularAlgebra[
		algebra.FiniteRing[S],
		S,
	], *constructions.FiniteRegularAlgebraElement[S], S] {
	coeffRing := algebra.StructureMustBeAs[algebra.FiniteRing[S]](p.Components()[0].CoefficientStructure())
	alg, _ := constructions.NewFiniteRegularAlgebra(coeffRing)
	out, _ := constructions.NewDirectSumModule(alg, uint(p.Arity().Uint64()))
	return out
}

// RegulariseScalars wraps each scalar value into a FiniteRegularAlgebraElement.
// The number of values must equal the arity of the direct sum.
func (p *DirectSumOfPolynomials[S]) RegulariseScalars(values ...S) ([]*constructions.FiniteRegularAlgebraElement[S], error) {
	if len(values) != int(p.Arity().Uint64()) {
		return nil, ErrValidation.WithMessage("incorrect component count")
	}
	out := make([]*constructions.FiniteRegularAlgebraElement[S], len(values))
	for i, v := range values {
		alg, err := p.CoefficientAlgebra().Factor().New(v)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not create regular algebra element")
		}
		out[i] = alg
	}
	return out, nil
}

// Eval evaluates every component polynomial at the given point and returns
// the results as a direct-sum element of regular algebra elements.
func (p *DirectSumOfPolynomials[S]) Eval(at S) *constructions.DirectSumModuleElement[*constructions.FiniteRegularAlgebraElement[S], S] {
	values, err := traits.EvalDirectProductOfPolynomialLikes(p, at)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not evaluate direct product of polynomials"))
	}
	regularised := make([]*constructions.FiniteRegularAlgebraElement[S], len(values))
	for i, v := range values {
		regularised[i], err = p.CoefficientAlgebra().Factor().New(v)
		if err != nil {
			panic(errs.Wrap(err).WithMessage("could not create regular algebra element"))
		}
	}
	out, err := p.CoefficientAlgebra().New(regularised...)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct product algebra element"))
	}
	return out
}

// NewDirectSumOfPolynomialModules constructs a direct sum of the given
// polynomial module with the specified arity (number of components).
func NewDirectSumOfPolynomialModules[C algebra.ModuleElement[C, S], S algebra.RingElement[S]](polyModule *PolynomialModule[C, S], arity uint) (*DirectSumOfPolynomialModules[C, S], error) {
	if arity == 0 {
		return nil, ErrValidation.WithMessage("arity must be greater than 0")
	}
	out := &DirectSumOfPolynomialModules[C, S]{}
	if err := out.Set(polyModule, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not set direct sum of polynomial modules")
	}
	var _ algebra.Module[*DirectSumOfModuleValuedPolynomials[C, S], S] = out
	return out, nil
}

// DirectSumOfPolynomialModules is the direct sum of module-valued polynomial
// modules. It implements algebra.Module[*DirectSumOfModuleValuedPolynomials[C, S], S].
type DirectSumOfPolynomialModules[C algebra.ModuleElement[C, S], S algebra.RingElement[S]] struct {
	traits.DirectSumModule[*PolynomialModule[C, S], *ModuleValuedPolynomial[C, S], S, *DirectSumOfModuleValuedPolynomials[C, S], DirectSumOfModuleValuedPolynomials[C, S]]
}

// Lift lifts a slice of scalar polynomials into a direct sum of module-valued
// polynomials by lifting each polynomial with the corresponding base point.
func (m *DirectSumOfPolynomialModules[C, S]) Lift(ps []*Polynomial[S], basePoints ...C) (*DirectSumOfModuleValuedPolynomials[C, S], error) {
	if len(ps) != int(m.Arity().Uint64()) {
		return nil, ErrValidation.WithMessage("polynomial count does not match arity")
	}
	if len(basePoints) != int(m.Arity().Uint64()) {
		return nil, ErrValidation.WithMessage("base points count does not match arity")
	}
	mps := make([]*ModuleValuedPolynomial[C, S], len(ps))
	var err error
	for i, p := range ps {
		mps[i], err = LiftPolynomial(p, basePoints[i])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not lift polynomial to exponent")
		}
	}
	out, err := m.New(mps...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create direct sum of module valued polynomials")
	}
	return out, nil
}

// CoefficientModule returns the direct sum of coefficient modules.
func (m *DirectSumOfPolynomialModules[C, S]) CoefficientModule() *constructions.DirectSumModule[algebra.Module[C, S], C, S] {
	coeffModule := algebra.StructureMustBeAs[algebra.Module[C, S]](m.Factor().CoefficientStructure())
	out, err := constructions.NewDirectSumModule(coeffModule, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct sum of coefficient modules"))
	}
	return out
}

// BaseAlgebra returns the direct sum of regular algebras formed from the
// scalar ring of the polynomial module.
func (m *DirectSumOfPolynomialModules[C, S]) BaseAlgebra() *constructions.DirectSumModule[
	*constructions.FiniteRegularAlgebra[
		algebra.FiniteRing[S], S,
	], *constructions.FiniteRegularAlgebraElement[S], S] {
	scalarRing := algebra.StructureMustBeAs[algebra.FiniteRing[S]](m.Factor().ScalarStructure())
	alg, err := constructions.NewFiniteRegularAlgebra(scalarRing)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create finite regular algebra"))
	}
	out, err := constructions.NewDirectSumModule(alg, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct sum of finite regular algebras"))
	}
	return out
}

// DirectSumOfModuleValuedPolynomials is an element of
// [DirectSumOfPolynomialModules]: a fixed-length tuple of module-valued
// polynomials.
type DirectSumOfModuleValuedPolynomials[C algebra.ModuleElement[C, S], S algebra.RingElement[S]] struct {
	traits.DirectSumModuleElement[*ModuleValuedPolynomial[C, S], S, *DirectSumOfModuleValuedPolynomials[C, S], DirectSumOfModuleValuedPolynomials[C, S]]
}

// Structure reconstructs the parent DirectSumOfPolynomialModules from the
// first component.
func (m *DirectSumOfModuleValuedPolynomials[C, S]) Structure() algebra.Structure[*DirectSumOfModuleValuedPolynomials[C, S]] {
	polyModule, ok := m.Components()[0].Structure().(*PolynomialModule[C, S])
	if !ok {
		panic(ErrValidation.WithMessage("component is not a polynomial module"))
	}
	out, err := NewDirectSumOfPolynomialModules(polyModule, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct sum of polynomial modules"))
	}
	return out
}

// CoefficientModule returns the direct sum of coefficient modules.
func (m *DirectSumOfModuleValuedPolynomials[C, S]) CoefficientModule() *constructions.DirectSumModule[algebra.Module[C, S], C, S] {
	coefficientModule := algebra.StructureMustBeAs[algebra.Module[C, S]](m.Components()[0].CoefficientStructure())
	out, err := constructions.NewDirectSumModule(coefficientModule, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct sum of coefficient modules"))
	}
	return out
}

// BaseRing returns the direct power ring of scalars matching the arity.
func (m *DirectSumOfModuleValuedPolynomials[C, S]) BaseRing() *constructions.DirectPowerRing[algebra.Ring[S], S] {
	polyModule, ok := m.Components()[0].Structure().(*PolynomialModule[C, S])
	if !ok {
		panic(ErrValidation.WithMessage("component is not a polynomial module"))
	}
	scalarRing := algebra.StructureMustBeAs[algebra.Ring[S]](polyModule.ScalarStructure())
	out, err := constructions.NewDirectPowerRing(scalarRing, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct power ring"))
	}
	return out
}

// Eval evaluates every component module-valued polynomial at the given scalar
// point and returns the results as a direct-sum element.
func (m *DirectSumOfModuleValuedPolynomials[C, S]) Eval(at S) *constructions.DirectSumModuleElement[C, S] {
	values, err := traits.EvalDirectProductOfPolynomialLikes(m, at)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not evaluate direct product of polynomials"))
	}
	out, err := m.CoefficientModule().New(values...)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct product algebra element"))
	}
	return out
}
