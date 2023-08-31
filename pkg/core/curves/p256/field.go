package p256

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.FieldProfile = (*FieldProfileP256)(nil)

type FieldProfileP256 struct{}

func (*FieldProfileP256) Curve() curves.Curve {
	return &p256Instance
}

func (*FieldProfileP256) Order() *saferith.Modulus {
	return fp.New().Params.Modulus
}

func (p *FieldProfileP256) Characteristic() *saferith.Nat {
	return p.Order().Nat()
}

func (*FieldProfileP256) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

var _ curves.FieldElement = (*FieldElementP256)(nil)

type FieldElementP256 struct {
	v *impl.Field

	_ helper_types.Incomparable
}

//nolint:revive // we don't care if impl shadows impl
func (e *FieldElementP256) impl() *impl.Field {
	return e.v
}

func (e *FieldElementP256) Value() curves.FieldValue {
	return e.v.Value[:]
}

func (e *FieldElementP256) Modulus() *saferith.Modulus {
	return e.v.Params.Modulus
}

func (e *FieldElementP256) Clone() curves.FieldElement {
	return &FieldElementP256{
		v: fp.New().Set(e.v),
	}
}

func (*FieldElementP256) Profile() curves.FieldProfile {
	return &FieldProfileP256{}
}

func (*FieldElementP256) New(value uint64) curves.FieldElement {
	t := fp.New()
	t.SetUint64(value)
	return &FieldElementP256{
		v: t,
	}
}

// Hash TODO: implement
func (*FieldElementP256) Hash(x []byte) curves.FieldElement {
	return nil
}

func (e *FieldElementP256) Cmp(rhs curves.FieldElement) int {
	rhse, ok := rhs.(*FieldElementP256)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.impl())
}

// Random TODO: implement
func (*FieldElementP256) Random(prng io.Reader) curves.FieldElement {
	return nil
}

func (*FieldElementP256) Zero() curves.FieldElement {
	return &FieldElementP256{
		v: fp.New().SetZero(),
	}
}

func (*FieldElementP256) One() curves.FieldElement {
	return &FieldElementP256{
		v: fp.New().SetOne(),
	}
}

func (e *FieldElementP256) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e *FieldElementP256) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e *FieldElementP256) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *FieldElementP256) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *FieldElementP256) Square() curves.FieldElement {
	return &FieldElementP256{
		v: e.v.Square(e.v),
	}
}

func (e *FieldElementP256) Double() curves.FieldElement {
	return &FieldElementP256{
		v: e.v.Double(e.v),
	}
}

func (e *FieldElementP256) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := fp.New().Sqrt(e.v)
	return &FieldElementP256{
		v: result,
	}, wasSquare
}

func (e *FieldElementP256) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElementP256) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementP256)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElementP256{
		v: fp.New().Add(e.v, n.impl()),
	}
}

func (e *FieldElementP256) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementP256)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElementP256{
		v: fp.New().Sub(e.v, n.impl()),
	}
}

func (e *FieldElementP256) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementP256)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElementP256{
		v: fp.New().Mul(e.v, n.impl()),
	}
}

func (e *FieldElementP256) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElementP256) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElementP256)
	if ok {
		v, wasInverted := fp.New().Invert(r.v)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElementP256{v: v}
	} else {
		panic("rhs is not ElementP256")
	}
}

func (e *FieldElementP256) Exp(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementP256)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElementP256{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e *FieldElementP256) Neg() curves.FieldElement {
	var out [impl.FieldLimbs]uint64
	e.v.Arithmetic.Neg(&out, &e.v.Value)
	return &FieldElementP256{
		v: e.v.Neg(e.v),
	}
}

func (e *FieldElementP256) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	e.v = fp.New().SetNat(value)
	return e, nil
}

func (e *FieldElementP256) Nat() *saferith.Nat {
	return e.v.Nat()
}

func (e *FieldElementP256) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != impl.FieldBytes {
		return nil, errs.NewInvalidLength("input length is not 32 bytes")
	}
	var out [32]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result, err := e.v.SetBytes(&out)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &FieldElementP256{
		v: result,
	}, nil
}

func (e *FieldElementP256) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) != impl.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length is not 64 bytes")
	}
	var out [64]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result := e.v.SetBytesWide(&out)
	return &FieldElementP256{
		v: result,
	}, nil
}

func (e *FieldElementP256) Bytes() []byte {
	result := e.v.Bytes()
	return result[:]
}

func (e *FieldElementP256) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a P256 scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElementP256) Scalar(curve curves.Curve) (curves.Scalar, error) {
	return curve.Scalar().SetNat(e.Nat())
}
