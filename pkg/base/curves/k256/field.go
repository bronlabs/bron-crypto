package k256

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/base/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
)

var _ curves.FieldProfile = (*FieldProfile)(nil)

type FieldProfile struct{}

func (*FieldProfile) Curve() curves.Curve {
	return &k256Instance
}

func (*FieldProfile) Order() *saferith.Modulus {
	return fp.New().Params.Modulus
}

func (p *FieldProfile) Characteristic() *saferith.Nat {
	return p.Order().Nat()
}

func (*FieldProfile) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

var _ curves.FieldElement = (*FieldElement)(nil)

type FieldElement struct {
	v *impl.Field

	_ helper_types.Incomparable
}

//nolint:revive // we don't care if impl shadows impl
func (e *FieldElement) impl() *impl.Field {
	return e.v
}

func (e *FieldElement) Value() curves.FieldValue {
	return e.v.Value[:]
}

func (e *FieldElement) Modulus() *saferith.Modulus {
	return e.v.Params.Modulus
}

func (e *FieldElement) Clone() curves.FieldElement {
	return &FieldElement{
		v: fp.New().Set(e.v),
	}
}

func (*FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

func (*FieldElement) New(value uint64) curves.FieldElement {
	t := fp.New()
	t.SetUint64(value)
	return &FieldElement{
		v: t,
	}
}

// Hash TODO: implement
func (*FieldElement) Hash(x []byte) curves.FieldElement {
	return nil
}

func (e *FieldElement) Cmp(rhs curves.FieldElement) int {
	rhsK256, ok := rhs.(*FieldElement)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhsK256.impl())
}

// Random TODO: implement
func (*FieldElement) Random(prng io.Reader) curves.FieldElement {
	return nil
}

func (*FieldElement) Zero() curves.FieldElement {
	return &FieldElement{
		v: fp.New().SetZero(),
	}
}

func (*FieldElement) One() curves.FieldElement {
	return &FieldElement{
		v: fp.New().SetOne(),
	}
}

func (e *FieldElement) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e *FieldElement) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e *FieldElement) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *FieldElement) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *FieldElement) Square() curves.FieldElement {
	return &FieldElement{
		v: e.v.Square(e.v),
	}
}

func (e *FieldElement) Double() curves.FieldElement {
	return &FieldElement{
		v: e.v.Double(e.v),
	}
}

func (e *FieldElement) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := fp.New().Sqrt(e.v)
	return &FieldElement{
		v: result,
	}, wasSquare
}

func (e *FieldElement) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElement) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElement{
		v: fp.New().Add(e.v, n.impl()),
	}
}

func (e *FieldElement) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElement{
		v: fp.New().Sub(e.v, n.impl()),
	}
}

func (e *FieldElement) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElement{
		v: fp.New().Mul(e.v, n.impl()),
	}
}

func (e *FieldElement) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElement) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElement)
	if ok {
		v, wasInverted := fp.New().Invert(r.v)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElement{v: v}
	} else {
		panic("rhs is not ElementK256")
	}
}

func (e *FieldElement) Exp(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElement{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e *FieldElement) Neg() curves.FieldElement {
	var out [impl.FieldLimbs]uint64
	e.v.Arithmetic.Neg(&out, &e.v.Value)
	return &FieldElement{
		v: e.v.Neg(e.v),
	}
}

func (e *FieldElement) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	e.v = fp.New().SetNat(value)
	return e, nil
}

func (e *FieldElement) Nat() *saferith.Nat {
	return e.v.Nat()
}

func (e *FieldElement) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != impl.FieldBytes {
		return nil, errs.NewInvalidLength("input length is not 32 bytes")
	}
	var out [32]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result, err := e.v.SetBytes(&out)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &FieldElement{
		v: result,
	}, nil
}

func (e *FieldElement) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) != impl.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length is not 64 bytes")
	}
	var out [64]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result := e.v.SetBytesWide(&out)
	return &FieldElement{
		v: result,
	}, nil
}

func (e *FieldElement) Bytes() []byte {
	result := e.v.Bytes()
	return result[:]
}

func (e *FieldElement) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a K256 scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElement) Scalar(curve curves.Curve) (curves.Scalar, error) {
	results, err := curve.Scalar().SetBytes(e.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert field element to scalar")
	}
	return results, nil
}
