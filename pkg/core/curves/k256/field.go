package k256

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.FieldProfile = (*FieldProfileK256)(nil)

type FieldProfileK256 struct{}

func (*FieldProfileK256) Curve() curves.Curve {
	return &k256Instance
}

func (*FieldProfileK256) Order() *saferith.Modulus {
	return fp.New().Params.Modulus
}

func (p *FieldProfileK256) Characteristic() *saferith.Nat {
	return p.Order().Nat()
}

func (*FieldProfileK256) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

var _ curves.FieldElement = (*FieldElementK256)(nil)

type FieldElementK256 struct {
	v *impl.Field

	_ helper_types.Incomparable
}

//nolint:revive // we don't care if impl shadows impl
func (e *FieldElementK256) impl() *impl.Field {
	return e.v
}

func (e *FieldElementK256) Value() curves.FieldValue {
	return e.v.Value[:]
}

func (e *FieldElementK256) Modulus() *saferith.Modulus {
	return e.v.Params.Modulus
}

func (e *FieldElementK256) Clone() curves.FieldElement {
	return &FieldElementK256{
		v: fp.New().Set(e.v),
	}
}

func (*FieldElementK256) Profile() curves.FieldProfile {
	return &FieldProfileK256{}
}

func (*FieldElementK256) New(value uint64) curves.FieldElement {
	t := fp.New()
	t.SetUint64(value)
	return &FieldElementK256{
		v: t,
	}
}

// Hash TODO: implement
func (*FieldElementK256) Hash(x []byte) curves.FieldElement {
	return nil
}

func (e *FieldElementK256) Cmp(rhs curves.FieldElement) int {
	rhsK256, ok := rhs.(*FieldElementK256)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhsK256.impl())
}

// Random TODO: implement
func (*FieldElementK256) Random(prng io.Reader) curves.FieldElement {
	return nil
}

func (*FieldElementK256) Zero() curves.FieldElement {
	return &FieldElementK256{
		v: fp.New().SetZero(),
	}
}

func (*FieldElementK256) One() curves.FieldElement {
	return &FieldElementK256{
		v: fp.New().SetOne(),
	}
}

func (e *FieldElementK256) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e *FieldElementK256) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e *FieldElementK256) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *FieldElementK256) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *FieldElementK256) Square() curves.FieldElement {
	return &FieldElementK256{
		v: e.v.Square(e.v),
	}
}

func (e *FieldElementK256) Double() curves.FieldElement {
	return &FieldElementK256{
		v: e.v.Double(e.v),
	}
}

func (e *FieldElementK256) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := fp.New().Sqrt(e.v)
	return &FieldElementK256{
		v: result,
	}, wasSquare
}

func (e *FieldElementK256) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElementK256) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementK256)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElementK256{
		v: fp.New().Add(e.v, n.impl()),
	}
}

func (e *FieldElementK256) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementK256)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElementK256{
		v: fp.New().Sub(e.v, n.impl()),
	}
}

func (e *FieldElementK256) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementK256)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElementK256{
		v: fp.New().Mul(e.v, n.impl()),
	}
}

func (e *FieldElementK256) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElementK256) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElementK256)
	if ok {
		v, wasInverted := fp.New().Invert(r.v)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElementK256{v: v}
	} else {
		panic("rhs is not ElementK256")
	}
}

func (e *FieldElementK256) Exp(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementK256)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElementK256{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e *FieldElementK256) Neg() curves.FieldElement {
	var out [impl.FieldLimbs]uint64
	e.v.Arithmetic.Neg(&out, &e.v.Value)
	return &FieldElementK256{
		v: e.v.Neg(e.v),
	}
}

func (e *FieldElementK256) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	e.v.SetNat(value)
	return e, nil
}

func (e *FieldElementK256) Nat() *saferith.Nat {
	return e.v.Nat()
}

func (e *FieldElementK256) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != impl.FieldBytes {
		return nil, errs.NewInvalidLength("input length is not 32 bytes")
	}
	var out [32]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result, err := e.v.SetBytes(&out)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &FieldElementK256{
		v: result,
	}, nil
}

func (e *FieldElementK256) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) != impl.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length is not 64 bytes")
	}
	var out [64]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result := e.v.SetBytesWide(&out)
	return &FieldElementK256{
		v: result,
	}, nil
}

func (e *FieldElementK256) Bytes() []byte {
	result := e.v.Bytes()
	return result[:]
}

func (e *FieldElementK256) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a K256 scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElementK256) Scalar(curve curves.Curve) (curves.Scalar, error) {
	results, err := curve.Scalar().SetBytes(e.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert field element to scalar")
	}
	return results, nil
}
