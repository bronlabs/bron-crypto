package bls12381

import (
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var (
	bls12381G1ScalarFieldInitOnce sync.Once
	bls12381G1ScalarFieldInstance ScalarField[G1]

	bls12381G2ScalarFieldInitOnce sync.Once
	bls12381G2ScalarFieldInstance ScalarField[G2]
)

var _ curves.ScalarField = (*ScalarField[G1])(nil)
var _ curves.ScalarField = (*ScalarField[G2])(nil)

type ScalarField[S SourceSubGroups] struct {
	_ types.Incomparable
}

func bls12381G1ScalarFieldInit() {
	bls12381G1ScalarFieldInstance = ScalarField[G1]{}
}

func bls12381G2ScalarFieldInit() {
	bls12381G2ScalarFieldInstance = ScalarField[G2]{}
}

func NewScalarFieldG1() *ScalarField[G1] {
	bls12381G1ScalarFieldInitOnce.Do(bls12381G1ScalarFieldInit)
	return &bls12381G1ScalarFieldInstance
}

func NewScalarFieldG2() *ScalarField[G2] {
	bls12381G2ScalarFieldInitOnce.Do(bls12381G2ScalarFieldInit)
	return &bls12381G2ScalarFieldInstance
}

func (*ScalarField[S]) Curve() curves.Curve {
	return GetSourceSubGroup[S]()
}

// === Basic Methods.

func (*ScalarField[_]) Name() string {
	return Name
}

func (*ScalarField[_]) Order() *saferith.Modulus {
	return r
}

func (sf *ScalarField[_]) Element() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (*ScalarField[_]) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (sf *ScalarField[_]) OperateOver(operator algebra.Operator, xs ...curves.Scalar) (curves.Scalar, error) {
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
		return nil, errs.NewInvalidType("operator %v is not supported", operator)
	}
	return current, nil
}

func (sf *ScalarField[_]) Random(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var buffer [base.WideFieldBytes]byte
	n, err := prng.Read(buffer[:])
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not read from prng")
	}
	if n != base.WideFieldBytes {
		return nil, errs.NewRandomSampleFailed("could not read enough bytes from prng")
	}
	res, _ := sf.Element().SetBytesWide(buffer[:])
	return res, nil
}

func (sf *ScalarField[_]) Hash(x []byte) (curves.Scalar, error) {
	u, err := sf.Curve().HashToScalars(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to scalar for bls12381g1 failed")
	}
	return u[0], nil
}

// === Additive Groupoid Methods.

func (*ScalarField[_]) Add(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Multiplicative Groupoid Methods.

func (*ScalarField[_]) Multiply(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Mul(y)
	}
	return result
}

// === Additive Monoid Methods.

func (*ScalarField[S]) AdditiveIdentity() curves.Scalar {
	return &Scalar{
		V: bls12381impl.FqNew().SetZero(),
		G: GetSourceSubGroup[S](),
	}
}

// === Multiplicative Monoid Methods.

func (*ScalarField[S]) MultiplicativeIdentity() curves.Scalar {
	return &Scalar{
		V: bls12381impl.FqNew().SetOne(),
		G: GetSourceSubGroup[S](),
	}
}

// === Additive Group Methods.

func (*ScalarField[_]) Sub(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Sub(y)
	}
	return result
}

// === Multiplicative Group Methods.

func (*ScalarField[_]) Div(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Div(y)
	}
	return result
}

// === Ring Methods.

func (*ScalarField[S]) QuadraticResidue(s curves.Scalar) (curves.Scalar, error) {
	ss, ok := s.(*Scalar)
	if !ok {
		return nil, errs.NewInvalidType("given point is not from this field")
	}
	ss.G = GetSourceSubGroup[S]()
	return ss.Sqrt()
}

// === Finite Field Methods.

func (sf *ScalarField[_]) Characteristic() *saferith.Nat {
	return sf.Order().Nat()
}

func (*ScalarField[_]) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

func (sf *ScalarField[S]) FrobeniusAutomorphism(e curves.Scalar) curves.Scalar {
	s := new(Scalar)
	s.G = GetSourceSubGroup[S]()
	return e.Exp(s.SetNat(sf.Characteristic()))
}

func (sf *ScalarField[_]) Trace(e curves.Scalar) curves.Scalar {
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

func (*ScalarField[_]) FieldBytes() int {
	return base.FieldBytes
}

func (*ScalarField[_]) WideFieldBytes() int {
	return base.WideFieldBytes
}

// === Zp Methods.

func (*ScalarField[S]) New(value uint64) curves.Scalar {
	return GetSourceSubGroup[S]().ScalarField().Element().SetNat(new(saferith.Nat).SetUint64(value))
}

func (sf *ScalarField[_]) Zero() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *ScalarField[_]) One() curves.Scalar {
	return sf.MultiplicativeIdentity()
}

// === Ordering Methods.

func (sf *ScalarField[_]) Top() curves.Scalar {
	return sf.Zero().Sub(sf.One())
}

func (sf *ScalarField[_]) Bottom() curves.Scalar {
	return sf.Zero()
}

func (*ScalarField[_]) Join(x, y curves.Scalar) curves.Scalar {
	return x.Join(y)
}

func (*ScalarField[_]) Meet(x, y curves.Scalar) curves.Scalar {
	return x.Meet(y)
}

func (*ScalarField[_]) Max(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	max := x
	for _, y := range ys {
		max = max.Max(y)
	}
	return max
}

func (*ScalarField[_]) Min(x curves.Scalar, ys ...curves.Scalar) curves.Scalar {
	min := x
	for _, y := range ys {
		min = min.Min(y)
	}
	return min
}
