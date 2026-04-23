package polynomials

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions/traits"
)

// LiftDirectPowerOfPolynomialsToExponent lifts a direct power of scalar polynomials
// into a direct power of module-valued polynomials by lifting each component with
// the corresponding base point.
func LiftDirectPowerOfPolynomialsToExponent[C algebra.ModuleElement[C, S], S algebra.RingElement[S]](dpow *DirectPowerOfPolynomials[S], basePoints ...C) (*DirectPowerOfModuleValuedPolynomials[C, S], error) {
	if dpow == nil {
		return nil, ErrValidation.WithMessage("dpow is nil")
	}
	if len(dpow.Components()) == 0 {
		return nil, ErrValidation.WithMessage("dpow must not be empty")
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
	dpowOfModules, err := NewDirectPowerOfPolynomialModules(polyModule, uint(dpow.Arity().Uint64()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create direct power of polynomial modules")
	}
	out, err := dpowOfModules.Lift(dpow.Components(), basePoints...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not lift direct power of polynomials to exponent")
	}
	return out, nil
}

// NewDirectPowerOfPolynomialRings constructs a direct power of the given polynomial
// ring with the specified arity (number of components).
func NewDirectPowerOfPolynomialRings[S algebra.RingElement[S]](polyRing *PolynomialRing[S], arity uint) (*DirectPowerOfPolynomialRings[S], error) {
	if arity == 0 {
		return nil, ErrValidation.WithMessage("arity must be greater than 0")
	}
	out := &DirectPowerOfPolynomialRings[S]{}
	if err := out.Set(polyRing, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not set direct power of polynomial rings")
	}
	var _ algebra.Module[*DirectPowerOfPolynomials[S], S] = out
	return out, nil
}

// DirectPowerOfPolynomialRings is the direct power of polynomial rings, viewed as
// a module over the scalar ring S. It implements
// algebra.Module[*DirectPowerOfPolynomials[S], S].
type DirectPowerOfPolynomialRings[S algebra.RingElement[S]] struct {
	traits.DirectPowerAlgebra[*PolynomialRing[S], *Polynomial[S], S, *DirectPowerOfPolynomials[S], DirectPowerOfPolynomials[S]]
}

// CoefficientAlgebra returns the direct power of regular algebras formed from
// the coefficient ring.
func (r *DirectPowerOfPolynomialRings[S]) CoefficientAlgebra() *constructions.DirectPowerModule[
	*constructions.FiniteRegularAlgebra[
		algebra.FiniteRing[S],
		S,
	],
	*constructions.FiniteRegularAlgebraElement[S],
	S,
] {
	coeffRing := algebra.StructureMustBeAs[algebra.FiniteRing[S]](r.Factor().ScalarStructure())
	alg := errs.Must1(constructions.NewFiniteRegularAlgebra(coeffRing))
	out := errs.Must1(constructions.NewDirectPowerModule(alg, uint(r.Arity().Uint64())))
	return out
}

// DirectPowerOfPolynomials is an element of [DirectPowerOfPolynomialRings]:
// a fixed-length tuple of scalar polynomials.
type DirectPowerOfPolynomials[S algebra.RingElement[S]] struct {
	traits.DirectPowerAlgebraElement[*Polynomial[S], S, *DirectPowerOfPolynomials[S], DirectPowerOfPolynomials[S]]
}

// Structure reconstructs the parent DirectPowerOfPolynomialRings from the
// first component.
func (p *DirectPowerOfPolynomials[S]) Structure() algebra.Structure[*DirectPowerOfPolynomials[S]] {
	arity := p.Arity()
	if arity.IsZero() {
		return nil
	}
	polyRing, ok := p.Components()[0].Structure().(*PolynomialRing[S])
	if !ok {
		panic(ErrValidation.WithMessage("component is not a polynomial ring"))
	}
	out := errs.Must1(NewDirectPowerOfPolynomialRings(polyRing, uint(arity.Uint64())))
	return out
}

// CoefficientAlgebra returns the direct power of regular algebras formed from
// the coefficient ring of the first component.
func (p *DirectPowerOfPolynomials[S]) CoefficientAlgebra() *constructions.DirectPowerModule[
	*constructions.FiniteRegularAlgebra[
		algebra.FiniteRing[S],
		S,
	], *constructions.FiniteRegularAlgebraElement[S], S] {
	coeffRing := algebra.StructureMustBeAs[algebra.FiniteRing[S]](p.Components()[0].CoefficientStructure())
	alg := errs.Must1(constructions.NewFiniteRegularAlgebra(coeffRing))
	out := errs.Must1(constructions.NewDirectPowerModule(alg, uint(p.Arity().Uint64())))
	return out
}

// RegulariseScalars wraps each scalar value into a FiniteRegularAlgebraElement.
// The number of values must equal the arity of the direct power.
func (p *DirectPowerOfPolynomials[S]) RegulariseScalars(values ...S) ([]*constructions.FiniteRegularAlgebraElement[S], error) {
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
// the results as a direct-power element of regular algebra elements.
func (p *DirectPowerOfPolynomials[S]) Eval(at S) *constructions.DirectPowerModuleElement[*constructions.FiniteRegularAlgebraElement[S], S] {
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

// NewDirectPowerOfPolynomialModules constructs a direct power of the given
// polynomial module with the specified arity (number of components).
func NewDirectPowerOfPolynomialModules[C algebra.ModuleElement[C, S], S algebra.RingElement[S]](polyModule *PolynomialModule[C, S], arity uint) (*DirectPowerOfPolynomialModules[C, S], error) {
	if arity == 0 {
		return nil, ErrValidation.WithMessage("arity must be greater than 0")
	}
	out := &DirectPowerOfPolynomialModules[C, S]{}
	if err := out.Set(polyModule, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not set direct power of polynomial modules")
	}
	var _ algebra.Module[*DirectPowerOfModuleValuedPolynomials[C, S], S] = out
	return out, nil
}

// DirectPowerOfPolynomialModules is the direct power of module-valued polynomial
// modules. It implements algebra.Module[*DirectPowerOfModuleValuedPolynomials[C, S], S].
type DirectPowerOfPolynomialModules[C algebra.ModuleElement[C, S], S algebra.RingElement[S]] struct {
	traits.DirectPowerModule[*PolynomialModule[C, S], *ModuleValuedPolynomial[C, S], S, *DirectPowerOfModuleValuedPolynomials[C, S], DirectPowerOfModuleValuedPolynomials[C, S]]
}

// Lift lifts a slice of scalar polynomials into a direct power of module-valued
// polynomials by lifting each polynomial with the corresponding base point.
func (m *DirectPowerOfPolynomialModules[C, S]) Lift(ps []*Polynomial[S], basePoints ...C) (*DirectPowerOfModuleValuedPolynomials[C, S], error) {
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
		return nil, errs.Wrap(err).WithMessage("could not create direct power of module valued polynomials")
	}
	return out, nil
}

// CoefficientModule returns the direct power of coefficient modules.
func (m *DirectPowerOfPolynomialModules[C, S]) CoefficientModule() *constructions.DirectPowerModule[algebra.Module[C, S], C, S] {
	coeffModule := algebra.StructureMustBeAs[algebra.Module[C, S]](m.Factor().CoefficientStructure())
	out, err := constructions.NewDirectPowerModule(coeffModule, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct power of coefficient modules"))
	}
	return out
}

// BaseAlgebra returns the direct power of regular algebras formed from the
// scalar ring of the polynomial module.
func (m *DirectPowerOfPolynomialModules[C, S]) BaseAlgebra() *constructions.DirectPowerModule[
	*constructions.FiniteRegularAlgebra[
		algebra.FiniteRing[S], S,
	], *constructions.FiniteRegularAlgebraElement[S], S] {
	scalarRing := algebra.StructureMustBeAs[algebra.FiniteRing[S]](m.Factor().ScalarStructure())
	alg, err := constructions.NewFiniteRegularAlgebra(scalarRing)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create finite regular algebra"))
	}
	out, err := constructions.NewDirectPowerModule(alg, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct power of finite regular algebras"))
	}
	return out
}

// DirectPowerOfModuleValuedPolynomials is an element of
// [DirectPowerOfPolynomialModules]: a fixed-length tuple of module-valued
// polynomials.
type DirectPowerOfModuleValuedPolynomials[C algebra.ModuleElement[C, S], S algebra.RingElement[S]] struct {
	traits.DirectPowerModuleElement[*ModuleValuedPolynomial[C, S], S, *DirectPowerOfModuleValuedPolynomials[C, S], DirectPowerOfModuleValuedPolynomials[C, S]]
}

// Structure reconstructs the parent DirectPowerOfPolynomialModules from the
// first component.
func (m *DirectPowerOfModuleValuedPolynomials[C, S]) Structure() algebra.Structure[*DirectPowerOfModuleValuedPolynomials[C, S]] {
	polyModule, ok := m.Components()[0].Structure().(*PolynomialModule[C, S])
	if !ok {
		panic(ErrValidation.WithMessage("component is not a polynomial module"))
	}
	out, err := NewDirectPowerOfPolynomialModules(polyModule, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct power of polynomial modules"))
	}
	return out
}

// CoefficientModule returns the direct power of coefficient modules.
func (m *DirectPowerOfModuleValuedPolynomials[C, S]) CoefficientModule() *constructions.DirectPowerModule[algebra.Module[C, S], C, S] {
	coefficientModule := algebra.StructureMustBeAs[algebra.Module[C, S]](m.Components()[0].CoefficientStructure())
	out, err := constructions.NewDirectPowerModule(coefficientModule, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("could not create direct power of coefficient modules"))
	}
	return out
}

// BaseRing returns the direct power ring of scalars matching the arity.
func (m *DirectPowerOfModuleValuedPolynomials[C, S]) BaseRing() *constructions.DirectPowerRing[algebra.Ring[S], S] {
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
// point and returns the results as a direct-power element.
func (m *DirectPowerOfModuleValuedPolynomials[C, S]) Eval(at S) *constructions.DirectPowerModuleElement[C, S] {
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
