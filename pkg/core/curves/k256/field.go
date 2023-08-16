package k256

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

var _ (curves.FieldProfile) = (*FieldProfile)(nil)

type FieldProfile struct{}

func (FieldProfile) Curve() curves.Curve {
	return k256Instance
}

func (FieldProfile) Order() *big.Int {
	return fp.New().Params.BiModulus
}

func (p *FieldProfile) Characteristic() *big.Int {
	return p.Order()
}

func (FieldProfile) ExtensionDegree() *big.Int {
	return big.NewInt(1)
}

var _ (curves.FieldElement) = (*FieldElement)(nil)

type FieldElement struct {
	v *impl.Field
}

//nolint:revive // we don't care if impl shadows impl
func (e *FieldElement) impl() *impl.Field {
	return e.v
}

func (e FieldElement) Value() curves.FieldValue {
	return e.v.Value
}

func (e FieldElement) Modulus() curves.FieldValue {
	return e.v.Params.Modulus
}

func (e FieldElement) Clone() curves.FieldElement {
	return FieldElement{
		v: fp.New().Set(e.v),
	}
}

func (FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

func (e FieldElement) New(value int) curves.FieldElement {
	t := fp.New()
	v := new(big.Int).Mod(big.NewInt(int64(value)), e.v.Params.BiModulus)
	return &FieldElement{
		v: t.SetBigInt(v),
	}
}

// IMPLEMENT
func (FieldElement) Hash(x []byte) curves.FieldElement {
	return nil
}

func (e FieldElement) Cmp(rhs curves.FieldElement) int {
	rhse, ok := rhs.(FieldElement)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.impl())
}

// IMPLEMENT
func (FieldElement) Random(prng io.Reader) curves.FieldElement {
	return nil
}

func (FieldElement) Zero() curves.FieldElement {
	return &FieldElement{
		v: fp.New().SetZero(),
	}
}

func (FieldElement) One() curves.FieldElement {
	return &FieldElement{
		v: fp.New().SetOne(),
	}
}

func (e FieldElement) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e FieldElement) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e FieldElement) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e FieldElement) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e FieldElement) Square() curves.FieldElement {
	return &FieldElement{
		v: e.v.Square(e.v),
	}
}

func (e FieldElement) Double() curves.FieldElement {
	return &FieldElement{
		v: e.v.Double(e.v),
	}
}

func (e FieldElement) Sqrt() curves.FieldElement {
	result, wasSquare := fp.New().Sqrt(e.v)
	if !wasSquare {
		panic("couln't take sqrt")
	}
	return &FieldElement{
		v: result,
	}
}

func (e FieldElement) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e FieldElement) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(FieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElement{
		v: fp.New().Add(e.v, n.impl()),
	}
}

func (e FieldElement) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(FieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElement{
		v: fp.New().Sub(e.v, n.impl()),
	}
}

func (e FieldElement) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(FieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElement{
		v: fp.New().Mul(e.v, n.impl()),
	}
}

func (e FieldElement) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e FieldElement) Div(rhs curves.FieldElement) curves.FieldElement {
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

func (e FieldElement) Exp(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(FieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElement{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e FieldElement) Neg() curves.FieldElement {
	var out curves.FieldValue
	e.v.Arithmetic.Neg(&out, &e.v.Value)
	return nil
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
	result := e.v.Bytes()
	return result[:]
}

func (e FieldElement) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a K256 scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert from scalar")
	}
	return result, nil
}

func (e FieldElement) Scalar() (curves.FieldElement, error) {
	return nil, nil
}
