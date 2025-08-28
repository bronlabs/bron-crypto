package bf128

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// TODO: make to implement algera field, field element etc.

const (
	FieldElementSize  = 16
	FieldElementLimbs = 2
)

var (
	instance = &Field{}
)

type Field struct{}

func NewField() *Field {
	return instance
}

func (f *Field) FromBytes(buf []byte) (*FieldElement, error) {
	el := &FieldElement{}
	if len(buf) != FieldElementSize {
		return nil, errs.NewLength("invalid length of bytes for F2e128 element (is %d, should be %d)", len(buf), 16)
	}
	el[0] = binary.BigEndian.Uint64(buf[8:16])
	el[1] = binary.BigEndian.Uint64(buf[:8])
	return el, nil
}

func (f *Field) Select(choice uint64, x, y *FieldElement) *FieldElement {
	zSlice := ct.SliceSelect(ct.Choice(choice), x[:], y[:])
	return &FieldElement{
		zSlice[0],
		zSlice[1],
	}
}

type FieldElement [2]uint64

func (el *FieldElement) Add(y *FieldElement) *FieldElement {
	return &FieldElement{
		el[0] ^ y[0],
		el[1] ^ y[1],
	}
}

func (el *FieldElement) Mul(rhs *FieldElement) *FieldElement {
	// From section 2.3 of https://link.springer.com/book/10.1007/b97644, employing
	// the irreducible polynomial f(X) = X^128 + X^7 + X^2 + X + 1. (from Table A.1).
	var z [4]uint64
	var b = [3]uint64{rhs[0], rhs[1], 0}
	for k := 0; k < 64; k++ {
		for j := 0; j < FieldElementLimbs; j++ {
			// conditionally add a copy of shifted B to C, depending on the appropriate bit of A
			mask := -(el[j] >> k & 0x01) // if A[j] >> k & 0x01 == 1 then 0xFFF... else 0x000...
			for i := 0; i < FieldElementLimbs+1; i++ {
				z[j+i] ^= b[i] & mask
			}
		}
		for i := FieldElementLimbs; i > 0; i-- {
			b[i] = b[i]<<1 | b[i-1]>>63
		}
		b[0] <<= 1
	}
	// Modular reduction (stacked precomputation of Algorithm 2.40 in t, see Figure 2.9)
	for i := 2*FieldElementLimbs - 1; i >= FieldElementLimbs; i-- {
		z[i-2] ^= z[i] << 7
		z[i-1] ^= z[i] >> 57
		z[i-2] ^= z[i] << 2
		z[i-1] ^= z[i] >> 62
		z[i-2] ^= z[i] << 1
		z[i-1] ^= z[i] >> 63
		z[i-2] ^= z[i]
	}

	return (*FieldElement)(&[FieldElementLimbs]uint64{z[0], z[1]})
}

func (el *FieldElement) Bytes() []byte {
	buf := make([]byte, FieldElementSize)
	binary.BigEndian.PutUint64(buf[:8], el[1])
	binary.BigEndian.PutUint64(buf[8:16], el[0])
	return buf
}

func (el *FieldElement) Equal(rhs *FieldElement) bool {
	return ((el[0] ^ rhs[0]) | (el[1] ^ rhs[1])) == 0
}
