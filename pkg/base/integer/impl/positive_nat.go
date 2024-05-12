package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

func NewPositiveNatMixin[S algebra.Structure, E algebra.Element, N any](arithmetic integer.Arithmetic[N], unwrap func(E) N, v N) *PositiveNatMixin[S, E, N] {
	return &PositiveNatMixin[S, E, N]{
		arithmetic: arithmetic,
		unwrap:     unwrap,
		V:          v,
	}
}

type PositiveNatMixin[S algebra.Structure, E algebra.Element, N any] struct {
	algebra.StructuredSetElement[S, E]
	algebra.NatLike[E]
	arithmetic integer.Arithmetic[N]
	unwrap     func(E) N
	wrap       func(N) E
	V          N
}

func (n *PositiveNatMixin[S, E, N]) Equal(x *PositiveNatMixin[S, E, N]) bool {
	return n.arithmetic.Equal(n.V, x.V)
}

func (n *PositiveNatMixin[S, E, N]) Clone() PositiveNatMixin[S, E, N] {
	return PositiveNatMixin[S, E, N]{
		arithmetic: n.arithmetic,
		V:          n.arithmetic.Clone(n.V),
		unwrap:     n.unwrap,
	}
}

func (n *PositiveNatMixin[S, E, T]) HashCode() uint64 {
	return n.arithmetic.Uint64(n.V)
}

// func (n *PositiveNatMixin[S, E]) MarshalJSON() ([]byte, error) {
// 	marshaledValue, err := n.v.MarshalJSON()
// 	if err != nil {
// 		return nil, errs.WrapSerialisation(err, "could not marshal json the big int")
// 	}
// 	return json.Marshal(&struct {
// 		Name  string
// 		Value []byte
// 	}{
// 		Name:  string(n.arithmetic.Name()),
// 		Value: marshaledValue,
// 	})
// }

func (n *PositiveNatMixin[S, E, N]) Order(operator algebra.BinaryOperator[E]) (*saferith.Modulus, error) {
	panic("not here")
}

func (n *PositiveNatMixin[S, E, N]) ApplyOp(operator algebra.BinaryOperator[E], x algebra.GroupoidElement[S, E], count *saferith.Nat) (E, error) {
	panic("not here")
}

// func (n *PositiveNatMixin[S, E]) TrySub(x integer.Number[S, E]) (E, error) {
// 	xx, ok := x.(impl.Number[*BigInt])
// 	if !ok {
// 		return *new(E), errs.NewType("input is not of the right type")
// 	}
// 	outB, err := n.arithmetic.Sub(n.v, xx.Unwrap())
// 	if err != nil {
// 		return *new(E), errs.WrapFailed(err, "could not subtract")
// 	}
// 	res, err := n.new(&outB.Int)
// 	if err != nil {
// 		return *new(E), errs.WrapType(err, "could not wrap type")
// 	}
// 	return res, nil
// }

func (n *PositiveNatMixin[S, E, N]) ApplyAdd(x algebra.AdditiveGroupoidElement[S, E], count *saferith.Nat) E {
	xn, err := n.arithmetic.Mul(n.unwrap(x.Unwrap()), n.unwrap(n.SetNat(count)))
	if err != nil {
		panic(err)
	}
	res, err := n.arithmetic.Add(n.V, xn)
	if err != nil {
		panic(err)
	}
	return n.wrap(res)
}

// func (n *PositiveNatMixin[S, E]) Double() E {
// 	return n.Add(n.Unwrap())
// }

// func (n *PositiveNatMixin[S, E]) Triple() *PositiveNatMixin[S, E] {
// 	return n.Double().Add(n)
// }

// func (n *PositiveNatMixin[S, E]) Mul(x algebra.MultiplicativeGroupoidElement[*PositiveNumbers, *PositiveNatMixin[S, E]]) *PositiveNatMixin[S, E] {
// 	xx := x.Unwrap()
// 	res := &PositiveNatMixin[S, E]{v: Mul(n.v, xx.v)}
// 	if err := n.validate(xx.v, res.v); err != nil {
// 		panic(err)
// 	}
// 	return res
// }

func (n *PositiveNatMixin[S, E, N]) ApplyMul(x algebra.MultiplicativeGroupoidElement[S, E], count *saferith.Nat) E {
	xn, err := n.arithmetic.Exp(n.unwrap(x.Unwrap()), n.unwrap(n.SetNat(count)))
	if err != nil {
		panic(err)
	}
	res, err := n.arithmetic.Mul(n.V, xn)
	if err != nil {
		panic(err)
	}
	return n.wrap(res)
}

func (n *PositiveNatMixin[S, E, N]) Square() E {
	res, err := n.arithmetic.Square(n.V)
	if err != nil {
		panic(err)
	}
	return n.wrap(res)
}

func (n *PositiveNatMixin[S, E, N]) Cube() E {
	res, err := n.arithmetic.Cube(n.V)
	if err != nil {
		panic(err)
	}
	return n.wrap(res)
}

// func (n *PositiveNatMixin[S, E]) Exp(exponent *saferith.Nat) *PositiveNatMixin[S, E] {
// 	res := &PositiveNatMixin{
// 		v: Exp(n.v, exponent.Big()),
// 	}
// 	if err := n.validate(exponent.Big(), res.v); err != nil {
// 		panic(err)
// 	}
// 	return res
// }

func (n *PositiveNatMixin[S, E, N]) Cmp(rhs algebra.OrderTheoreticLatticeElement[S, E]) algebra.Ordering {
	return n.arithmetic.Cmp(n.V, n.unwrap(rhs.Unwrap()))
}

// func (n *PositiveNatMixin[S, E]) Join(rhs algebra.OrderTheoreticLatticeElement[*PositiveNumbers, *PositiveNatMixin[S, E]]) *PositiveNatMixin[S, E] {
// 	xx := rhs.Unwrap()
// 	res := &PositiveNatMixin[S, E]{v: Max(n.v, xx.v)}
// 	if err := n.validate(xx.v, res.v); err != nil {
// 		panic(err)
// 	}
// 	return res
// }

// func (n *PositiveNatMixin[S, E]) Meet(rhs algebra.OrderTheoreticLatticeElement[*PositiveNumbers, *PositiveNatMixin[S, E]]) *PositiveNatMixin[S, E] {
// 	xx := rhs.Unwrap()
// 	res := &PositiveNatMixin[S, E]{v: Min(n.v, xx.v)}
// 	if err := n.validate(xx.v, res.v); err != nil {
// 		panic(err)
// 	}
// 	return res
// }

// func (n *PositiveNatMixin[S, E]) Lattice() algebra.OrderTheoreticLattice[*PositiveNumbers, *PositiveNatMixin[S, E]] {
// 	return &PositiveNumbers{}
// }

// func (n *PositiveNatMixin[S, E]) Max(rhs *PositiveNatMixin[S, E]) *PositiveNatMixin[S, E] {
// 	xx := rhs.Unwrap()
// 	res := &PositiveNatMixin[S, E]{v: Max(n.v, xx.v)}
// 	if err := n.validate(xx.v, res.v); err != nil {
// 		panic(err)
// 	}
// 	return res
// }

// func (n *PositiveNatMixin[S, E]) Min(rhs *PositiveNatMixin[S, E]) *PositiveNatMixin[S, E] {
// 	xx := rhs.Unwrap()
// 	res := &PositiveNatMixin[S, E]{v: Min(n.v, xx.v)}
// 	if err := n.validate(xx.v, res.v); err != nil {
// 		panic(err)
// 	}
// 	return res
// }

// func (n *PositiveNatMixin[S, E]) Next() (*PositiveNatMixin[S, E], error) {
// 	res := n.Increment()
// 	if err := n.validate(res.v); err != nil {
// 		return res, err
// 	}
// 	return res, nil
// }

// func (n *PositiveNatMixin[S, E]) Previous() (*PositiveNatMixin[S, E], error) {
// 	res := n.Decrement()
// 	if err := n.validate(res.v); err != nil {
// 		return res, err
// 	}
// 	return res, nil
// }

// func (n *PositiveNatMixin[S, E]) Increment() *PositiveNatMixin[S, E] {
// 	res := &PositiveNatMixin[S, E]{
// 		v: Add(n.v, One),
// 	}
// 	if err := n.validate(res.v); err != nil {
// 		panic(err)
// 	}
// 	return res
// }

// func (n *PositiveNatMixin[S, E]) Decrement() *PositiveNatMixin[S, E] {
// 	res := &PositiveNatMixin[S, E]{
// 		v: Min(Sub(n.v, One), Zero),
// 	}
// 	if err := n.validate(res.v); err != nil {
// 		panic(err)
// 	}
// 	return res
// }

// func (n *PositiveNatMixin[S, E]) Uint64() uint64 {
// 	return n.v.Uint64()
// }

// func (n *PositiveNatMixin[S, E]) SetNat(v *saferith.Nat) *PositiveNatMixin[S, E] {
// 	return &PositiveNatMixin[S, E]{v: v.Big()}
// }

// func (n *PositiveNatMixin[S, E]) Nat() *saferith.Nat {
// 	return new(saferith.Nat).SetBig(n.v, -1)
// }

// func (n *PositiveNatMixin[S, E]) IsOne() bool {
// 	return Equal(n.v, One)
// }

// func (n *PositiveNatMixin[S, E]) IsEven() bool {
// 	return Equal(Mod(n.v, Two), Zero)
// }

// func (n *PositiveNatMixin[S, E]) IsOdd() bool {
// 	return !n.IsEven()
// }

// func (n *PositiveNatMixin[S, E]) IsPositive() bool {
// 	return !Equal(n.v, Zero) && Equal(Max(n.v, Zero), n.v)
// }

// func (n *PositiveNatMixin[S, E]) FromInt(v integer.Int) *PositiveNatMixin[S, E] {
// 	panic("not here")
// }

// func (n *PositiveNatMixin[S, E]) Int() integer.Int {
// 	panic("not here")
// }
