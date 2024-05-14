package groupoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type Groupoid[G algebra.Groupoid[G, E], E algebra.GroupoidElement[G, E]] struct{}

func (*Groupoid[G, E]) Cardinality() *saferith.Modulus {
	panic("in mixin")
}

func (*Groupoid[G, E]) GetOperator(op algebra.Operator) (algebra.BinaryOperator[E], bool) {
	panic("in mixin")
}

func (g *Groupoid[G, E]) Order() *saferith.Modulus {
	return g.Cardinality()
}

func (g *Groupoid[G, E]) Operate(under algebra.Operator, x algebra.GroupoidElement[G, E], ys ...algebra.GroupoidElement[G, E]) (E, error) {
	op, exists := g.GetOperator(under)
	if !exists {
		return *new(E), errs.NewMissing("structure is not defined under %s", under)
	}
	foldInput := make([]E, len(ys)+1)
	foldInput[0] = x.Unwrap()
	for i, y := range ys {
		foldInput[i+1] = y.Unwrap()
	}
	out, err := op.LFold(foldInput...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not apply the operator %s", under)
	}
	return out, nil
}

type AdditiveGroupoid[G algebra.AdditiveGroupoid[G, E], E algebra.AdditiveGroupoidElement[G, E]] struct {
	Groupoid[G, E]
}

func (*AdditiveGroupoid[G, E]) Addition() algebra.BinaryOperator[E] {
	panic("in mixin")
}

func (g *AdditiveGroupoid[G, E]) Add(x algebra.AdditiveGroupoidElement[G, E], ys ...algebra.AdditiveGroupoidElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

type MultiplicativeGroupoid[G algebra.MultiplicativeGroupoid[G, E], E algebra.MultiplicativeGroupoidElement[G, E]] struct {
	Groupoid[G, E]
}

func (*MultiplicativeGroupoid[G, E]) Multiplication() algebra.BinaryOperator[E] {
	panic("in mixin")
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
	Groupoid[G, E]
}

func (g *CyclicGroupoid[G, E]) BasePoint() E {
	panic("in mixin")
}

func (g *CyclicGroupoid[G, E]) Generator() E {
	return g.BasePoint()
}
