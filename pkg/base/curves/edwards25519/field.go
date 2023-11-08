package edwards25519

import (
	"encoding/binary"
	"io"

	"filippo.io/edwards25519/field"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.FieldProfile = (*FieldProfile)(nil)

type FieldProfile struct{}

func (*FieldProfile) Curve() curves.Curve {
	return &edwards25519Instance
}

func (*FieldProfile) Order() *saferith.Modulus {
	return baseFieldOrder
}

func (*FieldProfile) Characteristic() *saferith.Nat {
	return baseFieldOrder.Nat()
}

func (*FieldProfile) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

func (*FieldProfile) FieldBytes() int {
	return constants.FieldBytes
}

func (*FieldProfile) WideFieldBytes() int {
	return constants.WideFieldBytes
}

var _ curves.FieldElement = (*FieldElement)(nil)

type FieldElement struct {
	v *field.Element

	_ types.Incomparable
}

func (*FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

func (*FieldElement) Hash(x []byte) (curves.FieldElement, error) {
	els, err := New().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash to field element in edwards25519")
	}
	return els[0], nil
}

const maskLow51Bits uint64 = (1 << 51) - 1

func (e *FieldElement) Value() curves.FieldValue {
	// Since we don't have access to the internals of the field.Element, we instead
	// reproduce its `SetBytes` method to manually construct the field limbs.
	x := e.v.Bytes()
	v := make([]uint64, 5)
	// Bits 0:51 (bytes 0:8, bits 0:64, shift 0, mask 51).
	v[0] = binary.LittleEndian.Uint64(x[0:8])
	v[0] &= maskLow51Bits
	// Bits 51:102 (bytes 6:14, bits 48:112, shift 3, mask 51).
	v[1] = binary.LittleEndian.Uint64(x[6:14]) >> 3
	v[1] &= maskLow51Bits
	// Bits 102:153 (bytes 12:20, bits 96:160, shift 6, mask 51).
	v[2] = binary.LittleEndian.Uint64(x[12:20]) >> 6
	v[2] &= maskLow51Bits
	// Bits 153:204 (bytes 19:27, bits 152:216, shift 1, mask 51).
	v[3] = binary.LittleEndian.Uint64(x[19:27]) >> 1
	v[3] &= maskLow51Bits
	// Bits 204:255 (bytes 24:32, bits 192:256, shift 12, mask 51).
	// Note: not bytes 25:33, shift 4, to avoid overread.
	v[4] = binary.LittleEndian.Uint64(x[24:32]) >> 12
	v[4] &= maskLow51Bits
	return v
}

func (*FieldElement) Modulus() *saferith.Modulus {
	return baseFieldOrder
}

func (e *FieldElement) Clone() curves.FieldElement {
	return &FieldElement{
		v: new(field.Element).Set(e.v),
	}
}

func (e *FieldElement) Cmp(rhs curves.FieldElement) int {
	n, ok := rhs.(*FieldElement)
	if !ok {
		return -2
	}
	if e.v.Equal(n.v) == 1 {
		return 0
	}
	v := e.v.Subtract(e.v, n.v)
	if v.IsNegative() == 1 {
		return -1
	}
	return 1
}

func (e *FieldElement) SubfieldElement(index uint64) curves.FieldElement {
	return e
}

func (*FieldElement) New(value uint64) curves.FieldElement {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	el, err := new(field.Element).SetBytes(buf)
	if err != nil {
		panic(err)
	}
	return &FieldElement{
		v: el,
	}
}

func (*FieldElement) Random(prng io.Reader) (curves.FieldElement, error) {
	buf := make([]byte, constants.FieldBytes)
	_, err := prng.Read(buf)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not read from prng")
	}
	el, err := new(field.Element).SetBytes(buf)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not set bytes of edwards25519 field element")
	}
	return &FieldElement{
		v: el,
	}, nil
}

func (*FieldElement) Zero() curves.FieldElement {
	return &FieldElement{
		v: new(field.Element).Zero(),
	}
}

func (*FieldElement) One() curves.FieldElement {
	return &FieldElement{
		v: new(field.Element).One(),
	}
}

var feZero = new(field.Element).Zero()

func (e *FieldElement) IsZero() bool {
	return e.v.Equal(feZero) == 1
}

var feOne = new(field.Element).Zero()

func (e *FieldElement) IsOne() bool {
	return e.v.Equal(feOne) == 1
}

func (e *FieldElement) IsOdd() bool {
	return e.v.Bytes()[0]&1 == 1
}

func (e *FieldElement) IsEven() bool {
	return e.v.Bytes()[0]&1 == 0
}

func (e *FieldElement) Square() curves.FieldElement {
	return &FieldElement{
		v: new(field.Element).Square(e.v),
	}
}

func (e *FieldElement) Double() curves.FieldElement {
	return &FieldElement{
		v: new(field.Element).Add(e.v, e.v),
	}
}

func (e *FieldElement) Sqrt() (curves.FieldElement, bool) {
	res, ok := e.v.SqrtRatio(e.v, feOne)
	if ok == 1 {
		return &FieldElement{
			v: res,
		}, true
	}
	return nil, false
}

func (e *FieldElement) Cube() curves.FieldElement {
	eSq := new(field.Element).Square(e.v)
	return &FieldElement{
		v: eSq.Multiply(eSq, e.v),
	}
}

func (e *FieldElement) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &FieldElement{
		v: new(field.Element).Add(e.v, n.v),
	}
}

func (e *FieldElement) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &FieldElement{
		v: new(field.Element).Subtract(e.v, n.v),
	}
}

func (e *FieldElement) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &FieldElement{
		v: new(field.Element).Multiply(e.v, n.v),
	}
}

func (e *FieldElement) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	yFe, ok := y.(*FieldElement)
	if !ok {
		panic("y is not an edwards25519 base field element")
	}
	zFe, ok := z.(*FieldElement)
	if !ok {
		panic("y is not an edwards25519 base field element")
	}
	v := new(field.Element).Multiply(e.v, yFe.v)
	return &FieldElement{
		v: v.Add(v, zFe.v),
	}
}

func (e *FieldElement) Div(rhs curves.FieldElement) curves.FieldElement {
	rhsFe, ok := rhs.(*FieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	inverted := new(field.Element).Invert(rhsFe.v)
	if inverted.Equal(feZero) == 1 {
		panic("inverse of rhs is zero. cannot divide")
	}
	return &FieldElement{
		v: inverted.Multiply(e.v, inverted),
	}
}

func (*FieldElement) Exp(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (e *FieldElement) Neg() curves.FieldElement {
	return &FieldElement{
		v: new(field.Element).Negate(e.v),
	}
}

func (*FieldElement) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	v, err := new(field.Element).SetBytes(bitstring.ReverseBytes(value.Bytes()))
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not set nat bytes")
	}
	return &FieldElement{
		v: v,
	}, nil
}

func (e *FieldElement) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBytes(e.v.Bytes())
}

func (e *FieldElement) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != constants.FieldBytes {
		return nil, errs.NewInvalidLength("input length != %d bytes", constants.FieldBytes)
	}
	result, err := e.v.SetBytes(input)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not set bytes")
	}
	return &FieldElement{
		v: result,
	}, nil
}

func (e *FieldElement) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) > constants.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length > %d bytes", constants.WideFieldBytes)
	}
	buffer := bitstring.ReverseAndPadBytes(input, 64-len(input))
	result, err := e.v.SetWideBytes(buffer)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not set bytes")
	}
	return &FieldElement{
		v: result,
	}, nil
}

func (e *FieldElement) Bytes() []byte {
	return e.v.Bytes()
}

func (e *FieldElement) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a ed25519 scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElement) Scalar(curve curves.Curve) (curves.Scalar, error) {
	ePrimeSubfield := new(field.Element).Pow22523(e.v)
	results, err := curve.Scalar().SetBytes(ePrimeSubfield.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert field element to scalar")
	}
	return results, nil
}
