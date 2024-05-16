package uint256

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

// Ring256 is a ring ℤ/2^256ℤ of integers modulo 2^256.
type Ring256 struct {
	_ ds.Incomparable
}

var _ algebra.IntegerRing[*Ring256, Uint256] = (*Ring256)(nil)

func (r *Ring256) Hash(digest []byte) (Uint256, error) {
	data, err := hashing.Hash(base.RandomOracleHashFunction, digest)
	if err != nil {
		return Uint256{}, errs.WrapHashing(err, "cannot compute digest")
	}
	num, err := r.Element().SetBytesWide(data)
	if err != nil {
		return Uint256{}, errs.WrapHashing(err, "cannot set bytes")
	}

	return num, nil
}

func (r *Ring256) Random(prng io.Reader) (Uint256, error) {
	bytes := make([]byte, RingBytes)
	_, err := io.ReadFull(prng, bytes)
	if err != nil {
		return Uint256{}, errs.WrapRandomSample(err, "cannot sample element")
	}

	el, err := r.Element().SetBytes(bytes)
	if err != nil {
		return Uint256{}, errs.WrapRandomSample(err, "cannot sample element")
	}

	return el, nil
}

func (*Ring256) Cardinality() *saferith.Nat {
	return mod2Pow256.Nat()
}

func (*Ring256) Contains(_ Uint256) bool {
	return true
}

func (*Ring256) Iterator() ds.Iterator[Uint256] {
	panic("not supported")
}

func (*Ring256) Element() Uint256 {
	return [4]uint64{0, 0, 0, 0}
}

func (*Ring256) Name() string {
	return Name
}

func (*Ring256) Order() *saferith.Modulus {
	return mod2Pow256
}

func (*Ring256) Operators() []algebra.BinaryOperator[Uint256] {
	// TODO implement me
	panic("implement me")
}

func (r *Ring256) Unwrap() *Ring256 {
	return r
}

func (*Ring256) Equal(_ *Ring256) bool {
	return true
}

func (*Ring256) HashCode() uint64 {
	return 1
}

func (*Ring256) Select(choice bool, x0, x1 Uint256) Uint256 {
	b := utils.BoolTo[uint64](choice)
	return Uint256{
		^(b-1)&x0[0] | (b-1)&x1[0],
		^(b-1)&x0[1] | (b-1)&x1[1],
		^(b-1)&x0[2] | (b-1)&x1[2],
		^(b-1)&x0[3] | (b-1)&x1[3],
	}
}

func (*Ring256) IsDefinedUnder(operator algebra.BinaryOperator[Uint256]) bool {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) Op(operator algebra.BinaryOperator[Uint256], x algebra.GroupoidElement[*Ring256, Uint256], ys ...algebra.GroupoidElement[*Ring256, Uint256]) (Uint256, error) {
	return x.Unwrap(), nil
}

func (*Ring256) Add(x algebra.AdditiveGroupoidElement[*Ring256, Uint256], ys ...algebra.AdditiveGroupoidElement[*Ring256, Uint256]) Uint256 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Add(y)
	}
	return z
}

func (*Ring256) Addition() algebra.Addition[Uint256] {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) Mul(x algebra.MultiplicativeGroupoidElement[*Ring256, Uint256], ys ...algebra.MultiplicativeGroupoidElement[*Ring256, Uint256]) Uint256 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Mul(y)
	}
	return z
}

func (*Ring256) Exp(b, power Uint256) Uint256 {
	return b.Exp(power.Nat())
}

func (*Ring256) SimExp(bases []algebra.MultiplicativeGroupoidElement[*Ring256, Uint256], exponents []*saferith.Nat) (Uint256, error) {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[*Ring256, Uint256], exponent *saferith.Nat) Uint256 {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[*Ring256, Uint256], exponents []*saferith.Nat) Uint256 {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) Multiplication() algebra.Multiplication[Uint256] {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) DiscreteExponentiation() algebra.DiscreteExponentiation[Uint256] {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) Identity(under algebra.BinaryOperator[Uint256]) (Uint256, error) {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) AdditiveIdentity() Uint256 {
	return Zero
}

func (*Ring256) MultiplicativeIdentity() Uint256 {
	return One
}

func (*Ring256) Characteristic() *saferith.Nat {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) Join(x, y algebra.OrderTheoreticLatticeElement[*Ring256, Uint256]) Uint256 {
	return x.Join(y)
}

func (*Ring256) Meet(x, y algebra.OrderTheoreticLatticeElement[*Ring256, Uint256]) Uint256 {
	return x.Join(y)
}

func (*Ring256) LatticeElement() algebra.OrderTheoreticLatticeElement[*Ring256, Uint256] {
	return Uint256{0, 0, 0, 0}
}

func (*Ring256) Max(x algebra.ChainElement[*Ring256, Uint256], ys ...algebra.ChainElement[*Ring256, Uint256]) Uint256 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Max(y.Unwrap())
	}

	return z
}

func (*Ring256) Min(x algebra.ChainElement[*Ring256, Uint256], ys ...algebra.ChainElement[*Ring256, Uint256]) Uint256 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Max(y.Unwrap())
	}

	return z
}

func (*Ring256) ChainElement() algebra.ChainElement[*Ring256, Uint256] {
	return Uint256{0, 0, 0, 0}
}

func (*Ring256) New(v uint64) Uint256 {
	return Uint256{0, 0, 0, 0}
}

func (*Ring256) One() Uint256 {
	return One
}

func (*Ring256) Zero() Uint256 {
	return Zero
}

func (*Ring256) And(x algebra.ConjunctiveGroupoidElement[*Ring256, Uint256], ys ...algebra.ConjunctiveGroupoidElement[*Ring256, Uint256]) Uint256 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.And(y.Unwrap())
	}

	return z
}

func (*Ring256) ConjunctiveIdentity() Uint256 {
	return Max
}

func (*Ring256) Or(x algebra.DisjunctiveGroupoidElement[*Ring256, Uint256], ys ...algebra.DisjunctiveGroupoidElement[*Ring256, Uint256]) Uint256 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Or(y.Unwrap())
	}

	return z
}

func (*Ring256) DisjunctiveIdentity() Uint256 {
	return Zero
}

func (*Ring256) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[*Ring256, Uint256], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[*Ring256, Uint256]) Uint256 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Xor(y.Unwrap())
	}

	return z
}

func (*Ring256) ExclusiveDisjunctiveIdentity() Uint256 {
	return Zero
}

func (*Ring256) ElementSize() int {
	return RingBytes
}

func (*Ring256) WideElementSize() int {
	return 2 * RingBytes
}

func (*Ring256) Sub(x algebra.AdditiveGroupElement[*Ring256, Uint256], ys ...algebra.AdditiveGroupElement[*Ring256, Uint256]) Uint256 {
	z := x.Unwrap()
	for _, y := range ys {
		z = z.Sub(y.Unwrap())
	}

	return z
}

func (*Ring256) QuadraticResidue(p algebra.RingElement[*Ring256, Uint256]) (Uint256, error) {
	// TODO implement me
	panic("implement me")
}

func (*Ring256) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[*Ring256, Uint256]) (bool, error) {
	// TODO implement me
	panic("implement me")
}
