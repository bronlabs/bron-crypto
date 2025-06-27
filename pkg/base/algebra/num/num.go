package num

import (
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type LiftableToZ interface {
	Lift() *Int
}

func Max[T LiftableToZ](a, b T) T {
	if a.Lift().IsLessThanOrEqual(b.Lift()) {
		return b
	}
	return a
}

func Min[T LiftableToZ](a, b T) T {
	if a.Lift().IsLessThanOrEqual(b.Lift()) {
		return a
	}
	return b
}

func GCD(a, b *Int) *Int {
	if a == nil || b == nil {
		panic("argument is nil")
	}
	out := new(big.Int).GCD(nil, nil, a.v.Big(), b.v.Big())
	return &Int{v: *new(saferith.Int).SetBig(out, -1)}
}

func LCM(a, b *Int) (*Int, error) {
	if a == nil || b == nil {
		panic("argument is nil")
	}
	g := GCD(a, b)
	absProd := a.Mul(b).Abs()
	return absProd.Lift().TryDiv(g)
}

type PrimeFactorisation[E algebra.UniqueFactorizationMonoidElement[E]] struct {
	n  E
	ps ds.Map[*NatPlus, *Nat]
}

func (pf *PrimeFactorisation[E]) N() E {
	return pf.n
}

func (pf *PrimeFactorisation[E]) PrimeFactors() ds.Map[*NatPlus, *Nat] {
	return pf.ps
}

func (pf *PrimeFactorisation[E]) IsPrimeProduct() bool {
	for _, k := range pf.ps.Iter() {
		if !k.IsOne() {
			return false
		}
	}
	return true
}

func NewPrimeFactorisation[E algebra.UniqueFactorizationMonoidElement[E]](n E, primeFactors ds.Map[*NatPlus, *Nat]) (*PrimeFactorisation[E], error) {
	if primeFactors == nil {
		return nil, errs.NewIsNil("argument")
	}
	if n.IsOpIdentity() {
		return nil, errs.NewValue("n must not be identity")
	}
	for p := range primeFactors.Iter() {
		if !p.Lift().IsProbablyPrime() {
			return nil, errs.NewValue("p must be prime")
		}
	}
	return &PrimeFactorisation[E]{n: n, ps: primeFactors}, nil
}

func EulerTotient[E algebra.UintLike[E]](pf *PrimeFactorisation[E]) (*Nat, error) {
	if pf == nil {
		return nil, errs.NewIsNil("argument")
	}
	out := Z().One()
	if pf.IsPrimeProduct() {
		for p := range pf.PrimeFactors().Iter() {
			out = out.Mul(p.Lift().Decrement())
		}
	} else {
		for p, k := range pf.PrimeFactors().Iter() {
			out = out.Mul(p.Lift().Exp(k.Lift().Decrement()).Mul(p.Lift().Decrement()))
		}
	}
	if out.IsNegative() {
		return nil, errs.NewValue("result is negative")
	}
	return out.Abs(), nil
}
