package uint128

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

type Ring128 struct {
	algebra.BoundedOrderTheoreticLattice[*Ring128, Uint128]
	_ ds.Incomparable
}

func (*Ring128) Arithmetic() integer.Arithmetic[Uint128] {
	panic("not implemented")
}

var _ integer.Zn[*Ring128, Uint128] = (*Ring128)(nil)

func (r *Ring128) Hash(digest []byte) (Uint128, error) {
	data, err := hashing.Hash(base.RandomOracleHashFunction, digest)
	if err != nil {
		return Uint128{}, errs.WrapHashing(err, "cannot compute digest")
	}
	num, err := r.Element().SetBytesWide(data)
	if err != nil {
		return Uint128{}, errs.WrapHashing(err, "cannot set bytes")
	}

	return num, nil
}

func (r *Ring128) Random(prng io.Reader) (Uint128, error) {
	bytes := make([]byte, RingBytes)
	_, err := io.ReadFull(prng, bytes)
	if err != nil {
		return Uint128{}, errs.WrapRandomSample(err, "cannot sample element")
	}

	el, err := r.Element().SetBytes(bytes)
	if err != nil {
		return Uint128{}, errs.WrapRandomSample(err, "cannot sample element")
	}

	return el, nil
}

func (*Ring128) GetOperator(op algebra.Operator) (algebra.BinaryOperator[Uint128], bool) {
	//TODO implement me
	panic("implement me")
}

func (*Ring128) Cardinality() *saferith.Modulus {
	return mod2Pow128
}

func (*Ring128) Contains(_ Uint128) bool {
	return true
}

func (*Ring128) Iter() <-chan Uint128 {
	panic("not supported")
}

func (*Ring128) Element() Uint128 {
	return Zero
}

func (*Ring128) Name() string {
	return Name
}

func (*Ring128) Order() *saferith.Modulus {
	return mod2Pow128
}

func (*Ring128) Operators() []algebra.Operator {
	// TODO implement me
	panic("implement me")
}

func (r *Ring128) Unwrap() *Ring128 {
	return r
}

func (*Ring128) Equal(_ *Ring128) bool {
	return true
}

func (*Ring128) HashCode() uint64 {
	return 1
}

func (*Ring128) Select(choice bool, x0, x1 Uint128) Uint128 {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) IsDefinedUnder(operator algebra.Operator) bool {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) Operate(operator algebra.Operator, x algebra.GroupoidElement[*Ring128, Uint128], ys ...algebra.GroupoidElement[*Ring128, Uint128]) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) Add(x algebra.AdditiveGroupoidElement[*Ring128, Uint128], ys ...algebra.AdditiveGroupoidElement[*Ring128, Uint128]) Uint128 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Add(y.Unwrap())
	}

	return z
}

func (*Ring128) Addition() algebra.Addition[Uint128] {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) Mul(x algebra.MultiplicativeGroupoidElement[*Ring128, Uint128], ys ...algebra.MultiplicativeGroupoidElement[*Ring128, Uint128]) Uint128 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Mul(y.Unwrap())
	}

	return z
}

func (*Ring128) Exp(b, power Uint128) Uint128 {
	return b.Exp(power.Nat())
}

func (*Ring128) SimExp(bases []algebra.MultiplicativeGroupoidElement[*Ring128, Uint128], exponents []*saferith.Nat) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[*Ring128, Uint128], exponent *saferith.Nat) Uint128 {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[*Ring128, Uint128], exponents []*saferith.Nat) Uint128 {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) Multiplication() algebra.Multiplication[Uint128] {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) DiscreteExponentiation() algebra.DiscreteExponentiation[Uint128] {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) Identity(under algebra.Operator) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) AdditiveIdentity() Uint128 {
	return Zero
}

func (*Ring128) MultiplicativeIdentity() Uint128 {
	return One
}

func (*Ring128) Characteristic() *saferith.Nat {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) Join(x algebra.OrderTheoreticLatticeElement[*Ring128, Uint128], ys ...algebra.OrderTheoreticLatticeElement[*Ring128, Uint128]) Uint128 {
	panic("not implemented")
}

func (*Ring128) Meet(x algebra.OrderTheoreticLatticeElement[*Ring128, Uint128], ys ...algebra.OrderTheoreticLatticeElement[*Ring128, Uint128]) Uint128 {
	panic("not implemented")
}

func (*Ring128) LatticeElement() algebra.OrderTheoreticLatticeElement[*Ring128, Uint128] {
	return Zero
}

func (*Ring128) Max(x algebra.ChainElement[*Ring128, Uint128], ys ...algebra.ChainElement[*Ring128, Uint128]) Uint128 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Max(y.Unwrap())
	}

	return z
}

func (*Ring128) Min(x algebra.ChainElement[*Ring128, Uint128], ys ...algebra.ChainElement[*Ring128, Uint128]) Uint128 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Max(y.Unwrap())
	}

	return z
}

func (*Ring128) ChainElement() algebra.ChainElement[*Ring128, Uint128] {
	return Zero
}

func (*Ring128) New(v uint64) Uint128 {
	return Uint128{
		Lo: v,
		Hi: 0,
	}
}

func (*Ring128) One() Uint128 {
	return One
}

func (*Ring128) Zero() Uint128 {
	return Zero
}

func (*Ring128) And(x algebra.ConjunctiveGroupoidElement[*Ring128, Uint128], ys ...algebra.ConjunctiveGroupoidElement[*Ring128, Uint128]) Uint128 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.And(y.Unwrap())
	}

	return z
}

func (*Ring128) ConjunctiveIdentity() Uint128 {
	return Max
}

func (*Ring128) Or(x algebra.DisjunctiveGroupoidElement[*Ring128, Uint128], ys ...algebra.DisjunctiveGroupoidElement[*Ring128, Uint128]) Uint128 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Or(y.Unwrap())
	}

	return z
}

func (*Ring128) DisjunctiveIdentity() Uint128 {
	return Zero
}

func (*Ring128) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[*Ring128, Uint128], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[*Ring128, Uint128]) Uint128 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Xor(y.Unwrap())
	}

	return z
}

func (*Ring128) ExclusiveDisjunctiveIdentity() Uint128 {
	return Zero
}

func (*Ring128) ElementSize() int {
	return RingBytes
}

func (*Ring128) WideElementSize() int {
	return 2 * RingBytes
}

func (*Ring128) Sub(x algebra.AdditiveGroupElement[*Ring128, Uint128], ys ...algebra.AdditiveGroupElement[*Ring128, Uint128]) Uint128 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Sub(y.Unwrap())
	}

	return z
}

func (*Ring128) QuadraticResidue(p algebra.RingElement[*Ring128, Uint128]) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (*Ring128) IsDecomposable(coprimeIdealNorms ...integer.Uint[*Ring128, Uint128]) (bool, error) {
	// TODO implement me
	panic("implement me")
}
