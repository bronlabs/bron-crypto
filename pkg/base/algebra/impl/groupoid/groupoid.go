package groupoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type Groupoid[G algebra.Groupoid[G, E], E algebra.GroupoidElement[G, E]] struct {
	algebra.Groupoid[G, E]
}

func (g *Groupoid[G, E]) Order() *saferith.Nat {
	return g.Cardinality().Nat()
}

func (g *Groupoid[G, E]) Operate(under algebra.Operator, x algebra.GroupoidElement[G, E], ys ...algebra.GroupoidElement[G, E]) (E, error) {
	op, exists := g.GetOperator(under)
	if !exists {
		return *new(E), errs.NewMissing("structure is not defined under %s", under)
	}
	out, err := operator.RFold(op, x, ys...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not apply the operator %s", under)
	}
	return out, nil
}

type AdditiveGroupoid[G algebra.AdditiveGroupoid[G, E], E algebra.AdditiveGroupoidElement[G, E]] struct {
	algebra.AdditiveGroupoid[G, E]
}

func (g *AdditiveGroupoid[G, E]) Add(x algebra.AdditiveGroupoidElement[G, E], ys ...algebra.AdditiveGroupoidElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

type MultiplicativeGroupoid[G algebra.MultiplicativeGroupoid[G, E], E algebra.MultiplicativeGroupoidElement[G, E]] struct {
	algebra.MultiplicativeGroupoid[G, E]
}

func (*MultiplicativeGroupoid[G, E]) Mul(x algebra.MultiplicativeGroupoidElement[G, E], ys ...algebra.MultiplicativeGroupoidElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Mul(y)
	}
	return sum.Unwrap()
}
func (*MultiplicativeGroupoid[G, E]) Exp(base algebra.MultiplicativeGroupoidElement[G, E], exponent *saferith.Nat) E {
	return base.Exp(exponent)
}

func (g *MultiplicativeGroupoid[G, E]) SimExp(bases []algebra.MultiplicativeGroupoidElement[G, E], exponents []*saferith.Nat) (E, error) {
	if len(bases) != len(exponents) {
		return *new(E), errs.NewSize("#bases != #exponents")
	}
	prod := g.Exp(bases[0], exponents[0])
	for i, bi := range bases[1:] {
		prod = prod.Mul(g.Exp(bi, exponents[i]))
	}
	return prod, nil
}

func (g *MultiplicativeGroupoid[G, E]) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[G, E], exponent *saferith.Nat) E {
	prod := g.Exp(bases[0], exponent)
	for _, bi := range bases[1:] {
		prod = prod.Mul(g.Exp(bi, exponent))
	}
	return prod
}

func (g *MultiplicativeGroupoid[G, E]) MultiExponentExp(base algebra.MultiplicativeGroupoidElement[G, E], exponents []*saferith.Nat) E {
	prod := g.Exp(base, exponents[0])
	for _, exp := range exponents[1:] {
		prod = prod.Mul(g.Exp(base, exp))
	}
	return prod
}

type CyclicGroupoid[G algebra.CyclicGroupoid[G, E], E algebra.CyclicGroupoidElement[G, E]] struct {
	algebra.CyclicGroupoid[G, E]
}

func (g *CyclicGroupoid[G, E]) Generator() E {
	return g.BasePoint()
}
