package pallas

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.FieldProfile = (*FieldProfilePallas)(nil)

type FieldProfilePallas struct{}

func (*FieldProfilePallas) Curve() curves.Curve {
	return &pallasInstance
}

func (*FieldProfilePallas) Order() *saferith.Modulus {
	return fp.Modulus
}

func (p *FieldProfilePallas) Characteristic() *saferith.Nat {
	return p.Order().Nat()
}

func (*FieldProfilePallas) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

var _ curves.FieldElement = (*FieldElementPallas)(nil)

type FieldElementPallas struct {
	v *fp.Fp

	_ helper_types.Incomparable
}

func (e *FieldElementPallas) Value() curves.FieldValue {
	v := e.v.ToRaw()
	return v[:]
}

func (*FieldElementPallas) Modulus() *saferith.Modulus {
	return fp.Modulus
}

func (e *FieldElementPallas) Clone() curves.FieldElement {
	return &FieldElementPallas{
		v: new(fp.Fp).Set(e.v),
	}
}

func (e *FieldElementPallas) Cmp(rhs curves.FieldElement) int {
	rhse, ok := rhs.(*FieldElementPallas)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.v)
}

func (*FieldElementPallas) Profile() curves.FieldProfile {
	return &FieldProfilePallas{}
}

// Hash TODO: implement
func (*FieldElementPallas) Hash(x []byte) curves.FieldElement {
	return nil
}

func (*FieldElementPallas) New(value uint64) curves.FieldElement {
	t := new(fp.Fp)
	t.SetUint64(value)
	return &FieldElementPallas{
		v: t,
	}
}

func (*FieldElementPallas) Random(prng io.Reader) curves.FieldElement {
	return nil
}

func (*FieldElementPallas) Zero() curves.FieldElement {
	return &FieldElementPallas{
		v: new(fp.Fp).SetZero(),
	}
}

func (*FieldElementPallas) One() curves.FieldElement {
	return &FieldElementPallas{
		v: new(fp.Fp).SetOne(),
	}
}

func (e *FieldElementPallas) IsZero() bool {
	return e.v.IsZero()
}

func (e *FieldElementPallas) IsOne() bool {
	return e.v.IsOne()
}

func (e *FieldElementPallas) IsOdd() bool {
	return e.v.IsOdd()
}

func (e *FieldElementPallas) IsEven() bool {
	return !e.v.IsOdd()
}

func (e *FieldElementPallas) Square() curves.FieldElement {
	return &FieldElementPallas{
		v: new(fp.Fp).Square(e.v),
	}
}

func (e *FieldElementPallas) Double() curves.FieldElement {
	return &FieldElementPallas{
		v: new(fp.Fp).Double(e.v),
	}
}

func (e *FieldElementPallas) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := new(fp.Fp).Sqrt(e.v)
	return &FieldElementPallas{
		v: result,
	}, wasSquare
}

func (e *FieldElementPallas) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElementPallas) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementPallas)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &FieldElementPallas{
		v: new(fp.Fp).Add(e.v, n.v),
	}
}

func (e *FieldElementPallas) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementPallas)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &FieldElementPallas{
		v: new(fp.Fp).Sub(e.v, n.v),
	}
}

func (e *FieldElementPallas) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementPallas)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &FieldElementPallas{
		v: new(fp.Fp).Mul(e.v, n.v),
	}
}

func (e *FieldElementPallas) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElementPallas) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElementPallas)
	if ok {
		v, wasInverted := new(fp.Fp).Invert(r.v)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElementPallas{v: v}
	} else {
		panic("rhs is not pallas base field element")
	}
}

func (e *FieldElementPallas) Exp(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementPallas)
	if !ok {
		panic("not a pallas base field element")
	}
	return &FieldElementPallas{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e *FieldElementPallas) Neg() curves.FieldElement {
	return &FieldElementPallas{
		v: new(fp.Fp).Neg(e.v),
	}
}

func (e *FieldElementPallas) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	e.v = new(fp.Fp).SetNat(value)
	return e, nil
}

func (e *FieldElementPallas) Nat() *saferith.Nat {
	return e.v.Nat()
}

func (e *FieldElementPallas) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != impl.FieldBytes {
		return nil, errs.NewInvalidLength("input length is not 32 bytes")
	}
	var out [32]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result, err := e.v.SetBytes(&out)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &FieldElementPallas{
		v: result,
	}, nil
}

func (e *FieldElementPallas) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) != impl.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length is not 64 bytes")
	}
	var out [64]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result := e.v.SetBytesWide(&out)
	return &FieldElementPallas{
		v: result,
	}, nil
}

func (e *FieldElementPallas) Bytes() []byte {
	v := e.v.Bytes()
	return v[:]
}

func (e *FieldElementPallas) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a pallas scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElementPallas) Scalar(curve curves.Curve) (curves.Scalar, error) {
	results, err := curve.Scalar().SetBytes(e.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert field element to scalar")
	}
	return results, nil
}
