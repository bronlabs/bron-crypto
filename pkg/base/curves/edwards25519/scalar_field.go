package edwards25519

import (
	"crypto/subtle"
	"io"
	"sync"

	filippo "filippo.io/edwards25519"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var (
	edwards25519ScalarFieldInitOnce sync.Once
	edwards25519ScalarFieldInstance ScalarField
)

var _ curves.ScalarField = (*ScalarField)(nil)

type ScalarField struct {
	_ ds.Incomparable
}

func edwards25519ScalarFieldInit() {
	edwards25519ScalarFieldInstance = ScalarField{}
}

func NewScalarField() *ScalarField {
	edwards25519ScalarFieldInitOnce.Do(edwards25519ScalarFieldInit)
	return &edwards25519ScalarFieldInstance
}

func (*ScalarField) Curve() curves.Curve {
	return NewCurve()
}

// === Basic Methods.

func (*ScalarField) Name() string {
	return Name
}

func (*ScalarField) Order() *saferith.Modulus {
	return NewCurve().SubGroupOrder()
}

func (sf *ScalarField) Element() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (*ScalarField) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (sf *ScalarField) OperateOver(operator algebra.Operator, xs ...curves.Scalar) (curves.Scalar, error) {
	var current curves.Scalar
	switch operator {
	case algebra.Addition:
		current = sf.AdditiveIdentity()
		for _, x := range xs {
			current = current.Add(x)
		}
	case algebra.Multiplication:
		current = sf.MultiplicativeIdentity()
		for _, x := range xs {
			current = current.Mul(x)
		}
	case algebra.PointAddition:
		fallthrough
	default:
		return nil, errs.NewType("operator %v is not supported", operator)
	}
	return current, nil
}

func (*ScalarField) Random(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [base.WideFieldBytes]byte
	_, err := io.ReadFull(prng, seed[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not read from prng")
	}
	value, err := NewScalar(0).SetBytesWide(seed[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return value, nil
}

func (*ScalarField) Hash(x []byte) (curves.Scalar, error) {
	u, err := NewCurve().HashToScalars(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to scalar failed for edwards25519")
	}
	return u[0], nil
}

func (*ScalarField) Select(choice int, x0, x1 curves.Scalar) curves.Scalar {
	x0s, ok0 := x0.(*Scalar)
	x1s, ok1 := x1.(*Scalar)
	if !ok0 || !ok1 {
		panic("Not a Edwards25519 scalar")
	}
	sBytes := x0s.Bytes()
	subtle.ConstantTimeCopy(choice, sBytes, x1s.V.Bytes())
	s, err := filippo.NewScalar().SetCanonicalBytes(sBytes)
	if err != nil {
		panic(err)
	}
	return &Scalar{V: s}
}

// === Additive Groupoid Methods.

func (*ScalarField) Add(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Multiplicative Groupoid Methods.

func (*ScalarField) Multiply(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Mul(y)
	}
	return result
}

// === Additive Monoid Methods.

func (*ScalarField) AdditiveIdentity() curves.Scalar {
	return &Scalar{
		V: filippo.NewScalar(),
	}
}

// === Multiplicative Monoid Methods.

func (*ScalarField) MultiplicativeIdentity() curves.Scalar {
	return &Scalar{
		V: filippo.NewScalar().Set(scOne),
	}
}

// === Additive Group Methods.

func (*ScalarField) Sub(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Sub(y)
	}
	return result
}

// === Multiplicative Group Methods.

func (*ScalarField) Div(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Div(y)
	}
	return result
}

// === Ring Methods.

func (*ScalarField) QuadraticResidue(s curves.Scalar) (curves.Scalar, error) {
	ss, ok := s.(*Scalar)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return ss.Sqrt()
}

// === Finite Field Methods.

func (sf *ScalarField) Characteristic() *saferith.Nat {
	return sf.Order().Nat()
}

func (*ScalarField) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

func (sf *ScalarField) FrobeniusAutomorphism(e curves.Scalar) curves.Scalar {
	return e.Exp(new(Scalar).SetNat(sf.Characteristic()))
}

func (sf *ScalarField) Trace(e curves.Scalar) curves.Scalar {
	result := e
	currentDegree := new(saferith.Nat).SetUint64(1)
	currentTerm := result
	for currentDegree.Eq(sf.ExtensionDegree()) == 1 {
		currentTerm = sf.FrobeniusAutomorphism(currentTerm)
		result = result.Add(currentTerm)
		currentDegree = utils.IncrementNat(currentDegree)
	}
	return result
}

func (*ScalarField) FieldBytes() int {
	return base.FieldBytes
}

func (*ScalarField) WideFieldBytes() int {
	return base.WideFieldBytes
}

// === Zp Methods.

func (*ScalarField) New(value uint64) curves.Scalar {
	return NewScalar(value)
}

func (sf *ScalarField) Zero() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *ScalarField) One() curves.Scalar {
	return sf.MultiplicativeIdentity()
}

// === Ordering Methods.

func (sf *ScalarField) Top() curves.Scalar {
	return sf.Zero().Sub(sf.One())
}

func (sf *ScalarField) Bottom() curves.Scalar {
	return sf.Zero()
}

func (*ScalarField) Join(x, y curves.Scalar) curves.Scalar {
	return x.Join(y)
}

func (*ScalarField) Meet(x, y curves.Scalar) curves.Scalar {
	return x.Meet(y)
}

func (*ScalarField) Max(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	max := x
	for _, y := range ys {
		max = max.Max(y)
	}
	return max
}

func (*ScalarField) Min(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	min := x
	for _, y := range ys {
		min = min.Min(y)
	}
	return min
}
