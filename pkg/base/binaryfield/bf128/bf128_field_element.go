package bf128

import (
	"encoding/binary"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var _ algebra.FiniteFieldElement[*Field, *FieldElement] = (*FieldElement)(nil)

// FieldElement is an element of the finite field GF(2^256), representing
// coordinates of a degree-255 binary polynomial in little-endian order.
type FieldElement struct {
	V [fieldLimbs]uint64
}

func NewElementFromBytes(buf []byte) *FieldElement {
	res, err := field2e128Instance.Element().SetBytes(buf[:fieldBytes])
	if err != nil {
		panic(err)
	}
	return res
}

func (el *FieldElement) Equal(e *FieldElement) bool {
	return el.Eq(e) == 1
}

func (el *FieldElement) Eq(e *FieldElement) int {
	return int(
		ct.Equal(el.V[1], e.V[1]) & ct.Equal(el.V[0], e.V[0]),
	)
}

func (el *FieldElement) Clone() *FieldElement {
	return &FieldElement{
		V: el.V,
	}
}

func (el *FieldElement) HashCode() uint64 {
	return el.V[0] ^ el.V[1]
}

func (*FieldElement) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

func (el *FieldElement) Uint64() uint64 {
	return el.V[0]
}

func (el *FieldElement) SetNat(v *saferith.Nat) *FieldElement {
	res, err := el.SetBytesWide(v.Bytes())
	if err != nil {
		panic(err)
	}
	return res
}

func (el *FieldElement) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBytes(el.Bytes())
}

func (el *FieldElement) Bytes() []byte {
	buf := make([]byte, fieldBytes)
	binary.BigEndian.PutUint64(buf[:8], el.V[1])
	binary.BigEndian.PutUint64(buf[8:16], el.V[0])
	return buf
}

func (*FieldElement) SetBytes(buf []byte) (*FieldElement, error) {
	el := &FieldElement{}
	if len(buf) != fieldBytes {
		return nil, errs.NewLength("invalid length of bytes for F2e128 element (is %d, should be %d)", len(buf), fieldBytes)
	}
	el.V[0] = binary.BigEndian.Uint64(buf[8:16])
	el.V[1] = binary.BigEndian.Uint64(buf[:8])
	return el, nil
}

func (el *FieldElement) SetBytesWide(buf []byte) (*FieldElement, error) {
	if len(buf) < fieldBytes {
		buf = bitstring.PadToLeft(buf, fieldBytes-len(buf))
	}
	res, err := el.SetBytes(buf[:fieldBytes]) // Modular reduction: truncate to fieldBytesF2e128.
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't set bytes wide")
	}
	return res, nil
}

func (el *FieldElement) Add(y algebra.AdditiveGroupoidElement[*Field, *FieldElement]) *FieldElement {
	rhs := y.Unwrap()
	return &FieldElement{
		V: [fieldLimbs]uint64{
			el.V[0] ^ rhs.V[0],
			el.V[1] ^ rhs.V[1],
		},
	}
}

func (el *FieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[*Field, *FieldElement], n *saferith.Nat) *FieldElement {
	nBytes := n.Bytes()
	nIsOdd := uint64(nBytes[len(nBytes)-1] & 0x01)
	return NewField().Select(nIsOdd, el, &FieldElement{})
}

func (*FieldElement) Double() *FieldElement {
	return zero
}

func (el *FieldElement) Triple() *FieldElement {
	return el.Clone()
}

func (el *FieldElement) IsAdditiveIdentity() bool {
	return ct.Equal(el.V[0]|el.V[1], 0) == 1
}

func (el *FieldElement) AdditiveInverse() *FieldElement {
	return el.Clone()
}

func (el *FieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[*Field, *FieldElement]) bool {
	return el.Equal(of.Unwrap())
}

func (el *FieldElement) Neg() *FieldElement {
	return el.Clone()
}

func (el *FieldElement) Sub(rhs algebra.AdditiveGroupElement[*Field, *FieldElement]) *FieldElement {
	return el.Add(rhs)
}

func (el *FieldElement) ApplySub(x algebra.AdditiveGroupElement[*Field, *FieldElement], n *saferith.Nat) *FieldElement {
	return el.ApplyAdd(x, n)
}

func (el *FieldElement) Mul(v algebra.MultiplicativeGroupoidElement[*Field, *FieldElement]) *FieldElement {
	// From section 2.3 of https://link.springer.com/book/10.1007/b97644, employing
	// the irreducible polynomial f(X) = X^128 + X^7 + X^2 + X + 1. (from Table A.1).
	rhs := v.Unwrap()
	var z [4]uint64
	var b = [3]uint64{rhs.V[0], rhs.V[1], 0}
	for k := 0; k < 64; k++ {
		for j := 0; j < fieldLimbs; j++ {
			// conditionally add a copy of shifted B to C, depending on the appropriate bit of A
			mask := -(el.V[j] >> k & 0x01) // if A[j] >> k & 0x01 == 1 then 0xFFF... else 0x000...
			for i := 0; i < fieldLimbs+1; i++ {
				z[j+i] ^= b[i] & mask
			}
		}
		for i := fieldLimbs; i > 0; i-- {
			b[i] = b[i]<<1 | b[i-1]>>63
		}
		b[0] <<= 1
	}
	// Modular reduction (stacked precomputation of Algorithm 2.40 in t, see Figure 2.9)
	for i := 2*fieldLimbs - 1; i >= fieldLimbs; i-- {
		z[i-2] ^= z[i] << 7
		z[i-1] ^= z[i] >> 57
		z[i-2] ^= z[i] << 2
		z[i-1] ^= z[i] >> 62
		z[i-2] ^= z[i] << 1
		z[i-1] ^= z[i] >> 63
		z[i-2] ^= z[i]
	}
	return &FieldElement{
		V: [fieldLimbs]uint64{z[0], z[1]},
	}
}

func (*FieldElement) ApplyMul(_ algebra.MultiplicativeGroupoidElement[*Field, *FieldElement], _ *saferith.Nat) *FieldElement {
	panic("not implemented (to be filled using Montgomery ladder)")
}

func (el *FieldElement) Square() *FieldElement {
	return el.Mul(el)
}

func (el *FieldElement) Cube() *FieldElement {
	return el.Mul(el).Mul(el)
}

func (el *FieldElement) IsMultiplicativeIdentity() bool {
	return field2e128Instance.MultiplicativeIdentity().Equal(el)
}

// === Ring element methods.

func (el *FieldElement) MulAdd(p, q algebra.RingElement[*Field, *FieldElement]) *FieldElement {
	return el.Mul(p).Add(q)
}

func (el *FieldElement) IsQuadraticResidue() bool {
	_, err := el.Sqrt()
	return err != nil
}

func (*FieldElement) Sqrt() (*FieldElement, error) {
	panic("not implemented")
}

// === Finite Field Methods.

func (*FieldElement) MultiplicativeInverse() (*FieldElement, error) {
	panic("not implemented")
}

func (el *FieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[*Field, *FieldElement]) bool {
	return el.Mul(of).Equal(field2e128Instance.MultiplicativeIdentity())
}

func (el *FieldElement) Div(rhs algebra.MultiplicativeGroupElement[*Field, *FieldElement]) (*FieldElement, error) {
	inv, err := rhs.MultiplicativeInverse()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get inverse")
	}
	return el.Mul(inv), nil
}

func (*FieldElement) ApplyDiv(_ algebra.MultiplicativeGroupElement[*Field, *FieldElement], _ *saferith.Nat) (*FieldElement, error) {
	panic("not implemented")
}

func (*FieldElement) Exp(*saferith.Nat) *FieldElement {
	panic("not implemented")
}

func (*FieldElement) Structure() *Field {
	return NewField()
}

func (el *FieldElement) Unwrap() *FieldElement {
	return el
}

func (*FieldElement) Order(operator algebra.BinaryOperator[*FieldElement]) (*saferith.Modulus, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) ApplyOp(operator algebra.BinaryOperator[*FieldElement], x algebra.GroupoidElement[*Field, *FieldElement], n *saferith.Nat) (*FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) IsIdentity(under algebra.BinaryOperator[*FieldElement]) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Inverse(under algebra.BinaryOperator[*FieldElement]) (*FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) IsInverse(of algebra.GroupElement[*Field, *FieldElement], under algebra.BinaryOperator[*FieldElement]) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[*FieldElement]) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) CoPrime(x *FieldElement) bool {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) GCD(x *FieldElement) (*FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) LCM(x *FieldElement) (*FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Factorise() []*FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) EuclideanDiv(x *FieldElement) (quotient, reminder *FieldElement) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	// TODO implement me
	panic("implement me")
}
