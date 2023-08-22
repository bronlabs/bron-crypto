package pallas

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ (curves.FieldProfile) = (*FieldProfile)(nil)

type FieldProfile struct{}

func (FieldProfile) Order() *big.Int {
	return fp.BiModulus
}

func (p *FieldProfile) Characteristic() *big.Int {
	return p.Order()
}

func (FieldProfile) ExtensionDegree() *big.Int {
	return big.NewInt(1)
}

var _ (curves.FieldElement) = (*FieldElement)(nil)

type FieldElement struct {
	v *fp.Fp

	_ helper_types.Incomparable
}

func (e FieldElement) Value() curves.FieldValue {
	v := e.v.ToRaw()
	return v[:]
}

func (FieldElement) Modulus() *big.Int {
	return fp.BiModulus
}

func (e FieldElement) Clone() curves.FieldElement {
	return FieldElement{
		v: new(fp.Fp).Set(e.v),
	}
}

func (e FieldElement) Cmp(rhs curves.FieldElement) int {
	rhse, ok := rhs.(FieldElement)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.v)
}

func (FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

// IMPLEMENT
func (FieldElement) Hash(x []byte) curves.FieldElement {
	return nil
}

func (e FieldElement) New(value int) curves.FieldElement {
	return &FieldElement{
		v: e.v.SetUint64(uint64(value)),
	}
}

func (FieldElement) Random(prng io.Reader) curves.FieldElement {
	return nil
}

func (FieldElement) Zero() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).SetZero(),
	}
}

func (FieldElement) One() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).SetOne(),
	}
}

func (e FieldElement) IsZero() bool {
	return e.v.IsZero()
}

func (e FieldElement) IsOne() bool {
	return e.v.IsOne()
}

func (e FieldElement) IsOdd() bool {
	return e.v.IsOdd()
}

func (e FieldElement) IsEven() bool {
	return !e.v.IsOdd()
}

func (e FieldElement) Square() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).Square(e.v),
	}
}

func (e FieldElement) Double() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).Double(e.v),
	}
}

func (e FieldElement) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := new(fp.Fp).Sqrt(e.v)
	return &FieldElement{
		v: result,
	}, wasSquare
}

func (e FieldElement) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e FieldElement) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(FieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &FieldElement{
		v: new(fp.Fp).Add(e.v, n.v),
	}
}

func (e FieldElement) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(FieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &FieldElement{
		v: new(fp.Fp).Sub(e.v, n.v),
	}
}

func (e FieldElement) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(FieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &FieldElement{
		v: new(fp.Fp).Mul(e.v, n.v),
	}
}

func (e FieldElement) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e FieldElement) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElement)
	if ok {
		v, wasInverted := new(fp.Fp).Invert(r.v)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElement{v: v}
	} else {
		panic("rhs is not pallas base field element")
	}
}

func (e FieldElement) Exp(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(FieldElement)
	if !ok {
		panic("not a pallas base field element")
	}
	return &FieldElement{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e FieldElement) Neg() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).Neg(e.v),
	}
}

func (e FieldElement) SetBigInt(value *big.Int) (curves.FieldElement, error) {
	return e.SetBytes(value.Bytes())
}

func (e FieldElement) BigInt() *big.Int {
	return e.v.BigInt()
}

func (e FieldElement) SetBytes(input []byte) (curves.FieldElement, error) {
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

func (e FieldElement) SetBytesWide(input []byte) (curves.FieldElement, error) {
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

func (e FieldElement) Bytes() []byte {
	v := e.v.Bytes()
	return v[:]
}

func (e FieldElement) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a pallas scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e FieldElement) Scalar(curve curves.Curve) (curves.Scalar, error) {
	results, err := curve.Scalar().SetBytes(e.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert field element to scalar")
	}
	return results, nil
}
