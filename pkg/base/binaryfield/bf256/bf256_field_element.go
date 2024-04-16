package bf256

import (
	"encoding/binary"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ algebra.AbstractFiniteFieldElement[*Field, *FieldElement] = (*FieldElement)(nil)

// FieldElement is an element of the finite field GF(2^256), representing
// coordinates of a degree-255 binary polynomial in little-endian order.
type FieldElement struct {
	V [fieldLimbsF2e256]uint64
}

// === Basic Methods.

func (el *FieldElement) Equal(e *FieldElement) bool {
	return (ct.Equal(el.V[0], e.V[0]) &
		ct.Equal(el.V[1], e.V[1]) &
		ct.Equal(el.V[2], e.V[2]) &
		ct.Equal(el.V[3], e.V[3])) == 1
}

func (el *FieldElement) Clone() *FieldElement {
	clone := &FieldElement{}
	copy(clone.V[:], el.V[:])
	return clone
}

func (el *FieldElement) HashCode() uint64 {
	return el.V[0] ^ el.V[1] ^ el.V[2] ^ el.V[3]
}

func (*FieldElement) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

// === NatLike Methods.

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

// === BytesLike Methods.

func (el *FieldElement) Bytes() []byte {
	buf := make([]byte, fieldBytesF2e256)
	binary.BigEndian.PutUint64(buf[:8], el.V[3])
	binary.BigEndian.PutUint64(buf[8:16], el.V[2])
	binary.BigEndian.PutUint64(buf[16:24], el.V[1])
	binary.BigEndian.PutUint64(buf[24:32], el.V[0])
	return buf
}

func (*FieldElement) SetBytes(buf []byte) (*FieldElement, error) {
	el := &FieldElement{}
	if len(buf) != fieldBytesF2e256 {
		return nil, errs.NewLength("invalid length of bytes for F2e256 element (is %d, should be %d)", len(buf), fieldBytesF2e256)
	}
	el.V[0] = binary.BigEndian.Uint64(buf[24:32])
	el.V[1] = binary.BigEndian.Uint64(buf[16:24])
	el.V[2] = binary.BigEndian.Uint64(buf[8:16])
	el.V[3] = binary.BigEndian.Uint64(buf[:8])
	return el, nil
}

func (el *FieldElement) SetBytesWide(buf []byte) (*FieldElement, error) {
	if len(buf) < fieldBytesF2e256 {
		buf = bitstring.PadToLeft(buf, fieldBytesF2e256-len(buf))
	}
	res, err := el.SetBytes(buf[:fieldBytesF2e256]) // Modular reduction: truncate to fieldBytes.
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't set bytes wide")
	}
	return res, nil
}

// === Additive Group Methods.

func (el *FieldElement) Add(rhs *FieldElement) *FieldElement {
	return &FieldElement{
		V: [fieldLimbsF2e256]uint64{
			el.V[0] ^ rhs.V[0],
			el.V[1] ^ rhs.V[1],
			el.V[2] ^ rhs.V[2],
			el.V[3] ^ rhs.V[3],
		},
	}
}

func (el *FieldElement) ApplyAdd(x *FieldElement, n *saferith.Nat) *FieldElement {
	nBytes := n.Bytes()
	nIsOdd := nBytes[len(nBytes)-1]&0x01 == 1
	return NewField().Select(nIsOdd, el, &FieldElement{})
}

func (*FieldElement) Double() *FieldElement {
	return &FieldElement{}
}

func (el *FieldElement) Triple() *FieldElement {
	return el.Clone()
}

func (el *FieldElement) IsAdditiveIdentity() bool {
	return ct.Equal(el.V[0]|el.V[1]|el.V[2]|el.V[3], 0) == 1
}

func (el *FieldElement) AdditiveInverse() *FieldElement {
	return el.Clone()
}

func (el *FieldElement) IsAdditiveInverse(of *FieldElement) bool {
	return el.Equal(of)
}

func (el *FieldElement) Neg() *FieldElement {
	return el.Clone()
}

func (el *FieldElement) Sub(rhs *FieldElement) *FieldElement {
	return el.Add(rhs)
}

func (el *FieldElement) ApplySub(x *FieldElement, n *saferith.Nat) *FieldElement {
	return el.ApplyAdd(x, n)
}

// === Multiplicative Monoid Methods.

func (el *FieldElement) Mul(rhs *FieldElement) *FieldElement {
	// From section 2.3 of https://link.springer.com/book/10.1007/b97644 , employing
	// the irreducible polynomial f(X) = X^256 + X^10 + X^5 + X^2 + 1. (from Table A.1).
	var res [8]uint64
	var cumul = [5]uint64{rhs.V[0], rhs.V[1], rhs.V[2], rhs.V[3], 0}
	for k := 0; k < 64; k++ {
		for j := 0; j < fieldLimbsF2e256; j++ {
			// conditionally add a copy of shifted B to C, depending on the appropriate bit of A
			mask := -(el.V[j] >> k & 0x01) // if A[j] >> k & 0x01 == 1 then 0xFFF... else 0x000...
			for i := 0; i < fieldLimbsF2e256+1; i++ {
				res[j+i] ^= cumul[i] & mask
			}
		}
		for i := fieldLimbsF2e256; i > 0; i-- {
			cumul[i] = cumul[i]<<1 | cumul[i-1]>>63
		}
		cumul[0] <<= 1
	}
	// Modular reduction.
	for i := 2*fieldLimbsF2e256 - 1; i >= fieldLimbsF2e256; i-- {
		res[i-4] ^= res[i] << 10
		res[i-3] ^= res[i] >> 54
		res[i-4] ^= res[i] << 5
		res[i-3] ^= res[i] >> 59
		res[i-4] ^= res[i] << 2
		res[i-3] ^= res[i] >> 62
		res[i-4] ^= res[i]
	}
	return &FieldElement{
		V: [fieldLimbsF2e256]uint64{res[0], res[1], res[2], res[3]},
	}
}

func (*FieldElement) ApplyMul(x *FieldElement, n *saferith.Nat) *FieldElement {
	panic("not implemented (to be filled using Montgomery ladder)")
}

func (el *FieldElement) Square() *FieldElement {
	return el.Mul(el)
}

func (el *FieldElement) Cube() *FieldElement {
	return el.Mul(el).Mul(el)
}

func (el *FieldElement) IsMultiplicativeIdentity() bool {
	return field2e256Instance.MultiplicativeIdentity().Equal(el)
}

// === Ring element methods.

func (el *FieldElement) MulAdd(p, q *FieldElement) *FieldElement {
	return el.Mul(p).Add(q)
}

func (*FieldElement) Sqrt() (*FieldElement, error) {
	panic("not implemented")
}

// === Finite Field Methods.

func (*FieldElement) MultiplicativeInverse() *FieldElement {
	panic("not implemented")
}

func (el *FieldElement) IsMultiplicativeInverse(of *FieldElement) bool {
	return el.Mul(of).Equal(field2e256Instance.MultiplicativeIdentity())
}

func (el *FieldElement) Div(rhs *FieldElement) *FieldElement {
	return el.Mul(rhs.MultiplicativeInverse())
}

func (*FieldElement) ApplyDiv(x *FieldElement, n *saferith.Nat) *FieldElement {
	panic("not implemented")
}

func (*FieldElement) Exp(x *FieldElement) *FieldElement {
	panic("not implemented")
}
