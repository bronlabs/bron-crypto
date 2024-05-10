package bigint

import (
	"encoding/json"
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	"github.com/cronokirby/saferith"
)

var _ integer.NatPlus[*PositiveNumbers, *PositiveNat] = (*PositiveNat)(nil)

type PositiveNat struct {
	PositiveNatMixin[*PositiveNumbers, *PositiveNat]
}

func (*PositiveNat) Structure() *PositiveNumbers {
	return &PositiveNumbers{}
}

func (n *PositiveNat) Unwrap() *PositiveNat {
	return n
}

func (n *PositiveNat) New(x *big.Int) (*PositiveNat, error) {
	xx := new(BigInt).FromBig(x)
	if n.arithmetic.Cmp(xx, n.arithmetic.Zero()) == algebra.LessThan {
		return nil, errs.NewValue("input not in range")
	}
	return &PositiveNat{
		PositiveNatMixin[*PositiveNumbers, *PositiveNat]{
			v:          xx,
			new:        n.New,
			arithmetic: n.PositiveNatMixin.arithmetic,
		},
	}, nil
}

func (n *PositiveNat) Clone() *PositiveNat {
	return &PositiveNat{
		PositiveNatMixin[*PositiveNumbers, *PositiveNat]{
			v:          n.PositiveNatMixin.v.Clone(),
			new:        n.New,
			arithmetic: n.PositiveNatMixin.arithmetic,
		},
	}
}

type PositiveNatMixin[S algebra.Structure, E algebra.Element] struct {
	algebra.StructuredSetElement[S, E]
	arithmetic impl.Arithmetic[*BigInt]
	new        func(*big.Int) (E, error)
	v          *BigInt
}

func NewPositiveNat(v *big.Int) (*PositiveNat, error) {
	if v == nil {
		return nil, errs.NewIsNil("v")
	}
	vv := &BigInt{Int: *v}
	arithmetic := &BigArithmetic{}
	if arithmetic.Cmp(vv, arithmetic.One()) == algebra.LessThan {
		return nil, errs.NewValue("v < 1")
	}
	return &PositiveNat{
		PositiveNatMixin[*PositiveNumbers, *PositiveNat]{
			v:          vv,
			arithmetic: arithmetic.WithBottomAtOne(),
		},
	}, nil
}

func (n *PositiveNatMixin[S, E]) Equal(x *PositiveNatMixin[S, E]) bool {
	return n.arithmetic.Equal(n.v, x.v)
}

func (n *PositiveNatMixin[S, E]) HashCode() uint64 {
	return n.v.Uint64()
}

func (n *PositiveNatMixin[S, E]) MarshalJSON() ([]byte, error) {
	marshaledValue, err := n.v.MarshalJSON()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal json the big int")
	}
	return json.Marshal(&struct {
		Name  string
		Value []byte
	}{
		Name:  string(n.arithmetic.Name()),
		Value: marshaledValue,
	})
}

func (n *PositiveNatMixin[S, E]) Order(operator algebra.BinaryOperator[E]) (*saferith.Modulus, error) {
	panic("not here")
}

func (n *PositiveNatMixin[S, E]) ApplyOp(operator algebra.BinaryOperator[E], x algebra.GroupoidElement[*PositiveNumbers, *PositiveNatMixin[S, E]], count *saferith.Nat) (*PositiveNatMixin[S, E], error) {
	panic("not here")
}

func (n *PositiveNatMixin[S, E]) Add(x algebra.AdditiveGroupoidElement[S, E]) E {
	xx, ok := x.(impl.Number[*BigInt])
	if !ok {
		panic(errs.NewType("input is not of the right type"))
	}
	outB, err := n.arithmetic.Add(n.v, xx.Unwrap())
	if err != nil {
		panic(err)
	}
	res, err := n.new(&outB.Int)
	if err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) TrySub(x integer.Number[S, E]) (E, error) {
	xx, ok := x.(impl.Number[*BigInt])
	if !ok {
		return *new(E), errs.NewType("input is not of the right type")
	}
	outB, err := n.arithmetic.Sub(n.v, xx.Unwrap())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not subtract")
	}
	res, err := n.new(&outB.Int)
	if err != nil {
		return *new(E), errs.WrapType(err, "could not wrap type")
	}
	return res, nil
}

func (n *PositiveNatMixin[S, E]) ApplyAdd(x algebra.AdditiveGroupoidElement[S, E], count *saferith.Nat) E {
	xx, ok := x.(impl.Number[*BigInt])
	if !ok {
		panic(errs.NewType("input is not of the right type"))
	}
	xxn, err := n.arithmetic.Mul(xx.Unwrap(), new(BigInt).FromNat(count))
	if err != nil {
		panic(errs.WrapFailed(err, "could not compute x * coun"))
	}
	outB, err := n.arithmetic.Add(n.v, xxn)
	if err != nil {
		panic(errs.WrapFailed(err, "could not add n + x*n"))
	}
	res, err := n.new(&outB.Int)
	if err != nil {
		panic(errs.WrapType(err, "could not wrap type"))
	}
	return res
}

func (n *PositiveNatMixin[S, E]) Double() E {
	return n.Add(n.Unwrap())
}

func (n *PositiveNatMixin[S, E]) Triple() *PositiveNatMixin[S, E] {
	return n.Double().Add(n)
}

func (n *PositiveNatMixin[S, E]) Mul(x algebra.MultiplicativeGroupoidElement[*PositiveNumbers, *PositiveNatMixin[S, E]]) *PositiveNatMixin[S, E] {
	xx := x.Unwrap()
	res := &PositiveNatMixin[S, E]{v: Mul(n.v, xx.v)}
	if err := n.validate(xx.v, res.v); err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) ApplyMul(x algebra.MultiplicativeGroupoidElement[*PositiveNumbers, *PositiveNatMixin[S, E]], count *saferith.Nat) *PositiveNatMixin[S, E] {
	xx := x.Unwrap()
	res := &PositiveNatMixin[S, E]{
		v: Mul(n.v, Exp(xx.v, count.Big())),
	}
	if err := n.validate(xx.v, count.Big(), res.v); err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) Square() *PositiveNatMixin[S, E] {
	return n.Mul(n)
}

func (n *PositiveNatMixin[S, E]) Cube() *PositiveNatMixin[S, E] {
	return n.Square().Mul(n)
}

func (n *PositiveNatMixin[S, E]) Exp(exponent *saferith.Nat) *PositiveNatMixin[S, E] {
	res := &PositiveNatMixin{
		v: Exp(n.v, exponent.Big()),
	}
	if err := n.validate(exponent.Big(), res.v); err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) Cmp(rhs algebra.OrderTheoreticLatticeElement[*PositiveNumbers, *PositiveNatMixin[S, E]]) algebra.Ordering {
	xx := rhs.Unwrap()
	res := algebra.Ordering(n.v.Cmp(xx.v))
	if err := n.validate(xx.v); err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) Join(rhs algebra.OrderTheoreticLatticeElement[*PositiveNumbers, *PositiveNatMixin[S, E]]) *PositiveNatMixin[S, E] {
	xx := rhs.Unwrap()
	res := &PositiveNatMixin[S, E]{v: Max(n.v, xx.v)}
	if err := n.validate(xx.v, res.v); err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) Meet(rhs algebra.OrderTheoreticLatticeElement[*PositiveNumbers, *PositiveNatMixin[S, E]]) *PositiveNatMixin[S, E] {
	xx := rhs.Unwrap()
	res := &PositiveNatMixin[S, E]{v: Min(n.v, xx.v)}
	if err := n.validate(xx.v, res.v); err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) Lattice() algebra.OrderTheoreticLattice[*PositiveNumbers, *PositiveNatMixin[S, E]] {
	return &PositiveNumbers{}
}

func (n *PositiveNatMixin[S, E]) Max(rhs *PositiveNatMixin[S, E]) *PositiveNatMixin[S, E] {
	xx := rhs.Unwrap()
	res := &PositiveNatMixin[S, E]{v: Max(n.v, xx.v)}
	if err := n.validate(xx.v, res.v); err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) Min(rhs *PositiveNatMixin[S, E]) *PositiveNatMixin[S, E] {
	xx := rhs.Unwrap()
	res := &PositiveNatMixin[S, E]{v: Min(n.v, xx.v)}
	if err := n.validate(xx.v, res.v); err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) Chain() algebra.Chain[*PositiveNumbers, *PositiveNatMixin[S, E]] {
	return &PositiveNumbers{}
}

func (n *PositiveNatMixin[S, E]) Next() (*PositiveNatMixin[S, E], error) {
	res := n.Increment()
	if err := n.validate(res.v); err != nil {
		return res, err
	}
	return res, nil
}

func (n *PositiveNatMixin[S, E]) Previous() (*PositiveNatMixin[S, E], error) {
	res := n.Decrement()
	if err := n.validate(res.v); err != nil {
		return res, err
	}
	return res, nil
}

func (n *PositiveNatMixin[S, E]) Increment() *PositiveNatMixin[S, E] {
	res := &PositiveNatMixin[S, E]{
		v: Add(n.v, One),
	}
	if err := n.validate(res.v); err != nil {
		panic(err)
	}
	return res
}

func (n *PositiveNatMixin[S, E]) Decrement() *PositiveNatMixin[S, E] {
	res := &PositiveNatMixin[S, E]{
		v: Min(Sub(n.v, One), Zero),
	}
	if err := n.validate(res.v); err != nil {
		panic(err)
	}
	return res

}

func (n *PositiveNatMixin[S, E]) Uint64() uint64 {
	return n.v.Uint64()
}

func (n *PositiveNatMixin[S, E]) SetNat(v *saferith.Nat) *PositiveNatMixin[S, E] {
	return &PositiveNatMixin[S, E]{v: v.Big()}
}

func (n *PositiveNatMixin[S, E]) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.v, -1)
}

func (n *PositiveNatMixin[S, E]) IsOne() bool {
	return Equal(n.v, One)
}

func (n *PositiveNatMixin[S, E]) IsEven() bool {
	return Equal(Mod(n.v, Two), Zero)
}

func (n *PositiveNatMixin[S, E]) IsOdd() bool {
	return !n.IsEven()
}

func (n *PositiveNatMixin[S, E]) IsPositive() bool {
	return !Equal(n.v, Zero) && Equal(Max(n.v, Zero), n.v)
}

func (n *PositiveNatMixin[S, E]) FromInt(v integer.Int) *PositiveNatMixin[S, E] {
	panic("not here")
}

func (n *PositiveNatMixin[S, E]) Int() integer.Int {
	panic("not here")
}
