package polynomials

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func LiftDirectSumOfPolynomialsToExponent[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]](dsum *DirectSumOfPolynomials[S], basePoints ...C) (*DirectSumOfModuleValuedPolynomials[C, S], error) {
	if dsum == nil {
		return nil, errs.NewIsNil("dsum is nil")
	}
	if len(dsum.Components()) == 0 {
		return nil, errs.NewSize("dsum must not be empty")
	}
	if len(basePoints) == 0 {
		return nil, errs.NewSize("base points must not be empty")
	}
	coefficientModule, ok := basePoints[0].Structure().(algebra.Module[C, S])
	if !ok {
		return nil, errs.NewType("base point is not a module element")
	}
	polyModule, err := NewPolynomialModule(coefficientModule)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create polynomial module")
	}
	dsumOfModules, err := NewDirectSumOfPolynomialModules(polyModule, uint(dsum.Arity().Uint64()))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create direct sum of polynomial modules")
	}
	out, err := dsumOfModules.Lift(dsum.Components(), basePoints...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not lift direct sum of polynomials to exponent")
	}
	return out, nil
}

func NewDirectSumOfPolynomialRings[S algebra.FiniteRingElement[S]](polyRing PolynomialRing[S], arity uint) (*DirectSumOfPolynomialRings[S], error) {
	if arity == 0 {
		return nil, errs.NewIsZero("arity must be greater than 0")
	}
	out := &DirectSumOfPolynomialRings[S]{}
	out.Set(polyRing, arity)
	var _ algebra.Module[*DirectSumOfPolynomials[S], S] = out
	return out, nil
}

type DirectSumOfPolynomialRings[S algebra.FiniteRingElement[S]] struct {
	traits.DirectSumModule[PolynomialRing[S], Polynomial[S], S, *DirectSumOfPolynomials[S], DirectSumOfPolynomials[S]]
}

func (r *DirectSumOfPolynomialRings[S]) CoefficientAlgebra() *constructions.DirectSumModule[*constructions.FiniteRegularAlgebra[algebra.FiniteRing[S], S], *constructions.FiniteRegularAlgebraElement[S], S] {
	coeffRing, ok := r.Factor().CoefficientStructure().(algebra.FiniteRing[S])
	if !ok {
		panic(errs.NewType("coefficient structure is not a finite ring"))
	}
	alg, _ := constructions.NewFiniteRegularAlgebra(coeffRing)
	out, _ := constructions.NewDirectSumModule(alg, uint(r.Arity().Uint64()))
	return out
}

type DirectSumOfPolynomials[S algebra.FiniteRingElement[S]] struct {
	traits.DirectSumModuleElement[Polynomial[S], S, *DirectSumOfPolynomials[S], DirectSumOfPolynomials[S]]
}

func (p *DirectSumOfPolynomials[S]) Structure() algebra.Structure[*DirectSumOfPolynomials[S]] {
	arity := p.Arity()
	if arity.IsZero() {
		return nil
	}
	polyRing, ok := p.Components()[0].Structure().(PolynomialRing[S])
	if !ok {
		panic(errs.NewType("component is not a polynomial ring"))
	}
	out, _ := NewDirectSumOfPolynomialRings(polyRing, uint(arity.Uint64()))
	return out
}

func (p *DirectSumOfPolynomials[S]) IsDomain() bool {
	return false
}

func (r *DirectSumOfPolynomials[S]) CoefficientAlgebra() *constructions.DirectSumModule[*constructions.FiniteRegularAlgebra[algebra.FiniteRing[S], S], *constructions.FiniteRegularAlgebraElement[S], S] {
	coeffRing, ok := r.Components()[0].CoefficientStructure().(algebra.FiniteRing[S])
	if !ok {
		panic(errs.NewType("coefficient structure is not a finite ring"))
	}
	alg, _ := constructions.NewFiniteRegularAlgebra(coeffRing)
	out, _ := constructions.NewDirectSumModule(alg, uint(r.Arity().Uint64()))
	return out
}

func (p *DirectSumOfPolynomials[S]) RegulariseScalars(values ...S) ([]*constructions.FiniteRegularAlgebraElement[S], error) {
	if len(values) != int(p.Arity().Uint64()) {
		return nil, errs.NewLength("incorrect component count")
	}
	out := make([]*constructions.FiniteRegularAlgebraElement[S], len(values))
	for i, v := range values {
		alg, err := p.CoefficientAlgebra().Factor().New(v)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not create regular algebra element")
		}
		out[i] = alg
	}
	return out, nil
}

func (p *DirectSumOfPolynomials[S]) Eval(at S) *constructions.DirectSumModuleElement[*constructions.FiniteRegularAlgebraElement[S], S] {
	values, err := traits.EvalDirectProductOfPolynomialLikes(p, at)
	if err != nil {
		panic(errs.WrapFailed(err, "could not evaluate direct product of polynomials"))
	}
	regularised := make([]*constructions.FiniteRegularAlgebraElement[S], len(values))
	for i, v := range values {
		regularised[i], err = p.CoefficientAlgebra().Factor().New(v)
		if err != nil {
			panic(errs.WrapFailed(err, "could not create regular algebra element"))
		}
	}
	out, err := p.CoefficientAlgebra().New(regularised...)
	if err != nil {
		panic(errs.WrapFailed(err, "could not create direct product algebra element"))
	}
	return out
}

func NewDirectSumOfPolynomialModules[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]](polyModule PolynomialModule[C, S], arity uint) (*DirectSumOfPolynomialModules[C, S], error) {
	if arity == 0 {
		return nil, errs.NewIsZero("arity must be greater than 0")
	}
	out := &DirectSumOfPolynomialModules[C, S]{}
	out.Set(polyModule, arity)
	var _ algebra.Module[*DirectSumOfModuleValuedPolynomials[C, S], S] = out
	return out, nil
}

type DirectSumOfPolynomialModules[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]] struct {
	traits.DirectSumModule[PolynomialModule[C, S], ModuleValuedPolynomial[C, S], S, *DirectSumOfModuleValuedPolynomials[C, S], DirectSumOfModuleValuedPolynomials[C, S]]
}

func (m *DirectSumOfPolynomialModules[C, S]) Lift(ps []Polynomial[S], basePoints ...C) (*DirectSumOfModuleValuedPolynomials[C, S], error) {
	if len(ps) != int(m.Arity().Uint64()) {
		return nil, errs.NewLength("polynomial count does not match arity")
	}
	if len(basePoints) != int(m.Arity().Uint64()) {
		return nil, errs.NewLength("base points count does not match arity")
	}
	mps := make([]ModuleValuedPolynomial[C, S], len(ps))
	var err error
	for i, p := range ps {
		mps[i], err = LiftToExponent(p, basePoints[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not lift polynomial to exponent")
		}
	}
	out, err := m.New(mps...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create direct sum of module valued polynomials")
	}
	return out, nil
}

func (m *DirectSumOfPolynomialModules[C, S]) CoefficientModule() *constructions.DirectSumModule[algebra.Module[C, S], C, S] {
	out, _ := constructions.NewDirectSumModule(m.Factor().CoefficientStructure().(algebra.Module[C, S]), uint(m.Arity().Uint64()))
	return out
}

func (r *DirectSumOfPolynomialModules[C, S]) BaseAlgebra() *constructions.DirectSumModule[*constructions.FiniteRegularAlgebra[algebra.FiniteRing[S], S], *constructions.FiniteRegularAlgebraElement[S], S] {
	alg, _ := constructions.NewFiniteRegularAlgebra(r.Factor().ScalarStructure().(algebra.FiniteRing[S]))
	out, _ := constructions.NewDirectSumModule(alg, uint(r.Arity().Uint64()))
	return out
}

type DirectSumOfModuleValuedPolynomials[C algebra.ModuleElement[C, S], S algebra.FiniteRingElement[S]] struct {
	traits.DirectSumModuleElement[ModuleValuedPolynomial[C, S], S, *DirectSumOfModuleValuedPolynomials[C, S], DirectSumOfModuleValuedPolynomials[C, S]]
}

func (m *DirectSumOfModuleValuedPolynomials[C, S]) Structure() algebra.Structure[*DirectSumOfModuleValuedPolynomials[C, S]] {
	polyModule, ok := m.Components()[0].Structure().(PolynomialModule[C, S])
	if !ok {
		panic(errs.NewType("component is not a polynomial module"))
	}
	out, _ := NewDirectSumOfPolynomialModules(polyModule, uint(m.Arity().Uint64()))
	return out
}

func (m *DirectSumOfModuleValuedPolynomials[C, S]) CoefficientModule() *constructions.DirectSumModule[algebra.Module[C, S], C, S] {
	out, _ := constructions.NewDirectSumModule(m.Components()[0].CoefficientStructure().(algebra.Module[C, S]), uint(m.Arity().Uint64()))
	return out
}
func (m *DirectSumOfModuleValuedPolynomials[C, S]) BaseRing() *constructions.DirectPowerRing[algebra.FiniteRing[S], S] {
	polyModule, ok := m.Components()[0].Structure().(PolynomialModule[C, S])
	if !ok {
		panic(errs.NewType("component is not a polynomial module"))
	}
	out, _ := constructions.NewDirectPowerRing(polyModule.ScalarStructure().(algebra.FiniteRing[S]), uint(m.Arity().Uint64()))
	return out
}

func (m *DirectSumOfModuleValuedPolynomials[C, S]) Eval(at S) *constructions.DirectSumModuleElement[C, S] {
	values, err := traits.EvalDirectProductOfPolynomialLikes(m, at)
	if err != nil {
		panic(errs.WrapFailed(err, "could not evaluate direct product of polynomials"))
	}
	out, err := m.CoefficientModule().New(values...)
	if err != nil {
		panic(errs.WrapFailed(err, "could not create direct product algebra element"))
	}
	return out
}
