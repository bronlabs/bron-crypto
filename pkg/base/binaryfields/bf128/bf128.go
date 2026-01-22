package bf128

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"math/bits"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	Name              = "F_{2^128}"
	FieldElementSize  = 16
	FieldElementLimbs = 2
)

var (
	instance = &Field{}

	_ algebra.FieldExtension[*FieldElement]        = (*Field)(nil)
	_ algebra.FiniteField[*FieldElement]           = (*Field)(nil)
	_ algebra.FieldExtensionElement[*FieldElement] = (*FieldElement)(nil)
	_ algebra.FiniteFieldElement[*FieldElement]    = (*FieldElement)(nil)
)

type Field struct{}

func NewField() *Field {
	return instance
}

func (f *Field) Random(prng io.Reader) (*FieldElement, error) {
	var data [16]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to read random bytes")
	}
	return f.FromBytes(data[:])
}

func (f *Field) RandomNonZero(prng io.Reader) (*FieldElement, error) {
	e, err := f.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random element")
	}
	for e.IsZero() {
		e, err = f.Random(prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to generate random element")
		}
	}
	return e, nil
}

func (f *Field) Hash(data []byte) (*FieldElement, error) {
	h, err := blake2b.New(FieldElementSize, nil)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create hasher")
	}
	_, err = h.Write(data)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to write to hasher")
	}
	return f.FromBytes(h.Sum(nil))
}

func (*Field) Name() string {
	return Name
}

func (*Field) Order() cardinal.Cardinal {
	orderBig := new(big.Int)
	orderBig.SetBit(orderBig, 128, 1)
	return cardinal.NewFromBig(orderBig)
}

func (*Field) ElementSize() int {
	return FieldElementSize
}

func (*Field) Characteristic() cardinal.Cardinal {
	return cardinal.New(2)
}

func (f *Field) OpIdentity() *FieldElement {
	return f.Zero()
}

func (*Field) One() *FieldElement {
	return &FieldElement{1, 0}
}

func (*Field) Zero() *FieldElement {
	return &FieldElement{0, 0}
}

func (*Field) IsDomain() bool {
	return true
}

func (*Field) ExtensionDegree() uint {
	return 128
}

func (f *Field) FromComponentsBytes(data [][]byte) (*FieldElement, error) {
	if len(data) != 1 {
		return nil, ErrInvalidLength.WithMessage("invalid number of components for F2e128 element (is %d, should be 1)", len(data))
	}
	return f.FromBytes(data[0])
}

func (*Field) FromBytes(buf []byte) (*FieldElement, error) {
	el := &FieldElement{}
	if len(buf) != FieldElementSize {
		return nil, ErrInvalidLength.WithMessage("invalid length of bytes for F2e128 element (is %d, should be %d)", len(buf), 16)
	}
	el[0] = binary.BigEndian.Uint64(buf[8:16])
	el[1] = binary.BigEndian.Uint64(buf[:8])
	return el, nil
}

func (*Field) Select(choice uint64, x, y *FieldElement) *FieldElement {
	zSlice := ct.CSelectInts(ct.Choice(choice), x[:], y[:])
	return &FieldElement{
		zSlice[0],
		zSlice[1],
	}
}

type FieldElement [2]uint64

func (*FieldElement) Structure() algebra.Structure[*FieldElement] {
	return NewField()
}

func (el *FieldElement) Clone() *FieldElement {
	var clone FieldElement
	copy(clone[:], el[:])
	return &clone
}

func (el *FieldElement) HashCode() base.HashCode {
	return base.HashCode(el[0] ^ el[1])
}

func (el *FieldElement) String() string {
	return fmt.Sprintf("F2e128(%08x%08x)", el[1], el[0])
}

func (el *FieldElement) Op(e *FieldElement) *FieldElement {
	return el.Add(e)
}

func (el *FieldElement) OtherOp(e *FieldElement) *FieldElement {
	return el.Mul(e)
}

func (*FieldElement) Double() *FieldElement {
	return NewField().Zero()
}

func (el *FieldElement) Square() *FieldElement {
	return el.Mul(el)
}

func (el *FieldElement) IsOpIdentity() bool {
	return el.IsZero()
}

func (el *FieldElement) TryOpInv() (*FieldElement, error) {
	x := el.Neg()
	return x, nil
}

func (el *FieldElement) IsOne() bool {
	return (el[1] | (el[0] ^ 1)) == 0
}

func (el *FieldElement) TryInv() (*FieldElement, error) {
	if el.IsZero() {
		return nil, ErrDivisionByZero
	}

	b := NewField().Zero()
	c := NewField().One()
	u := &FieldElement{(1 << 7) | (1 << 2) | (1 << 1) | (1 << 0), 0}
	v := el.Clone()
	j := 128 - v.degree()
	u = u.Sub(v.shiftLeft(j))
	b = b.Sub(c.shiftLeft(j))

	for u.degree() > 0 {
		if u.degree() < v.degree() {
			u, v = v, u
			b, c = c, b
		}
		j = u.degree() - v.degree()
		u = u.Sub(v.shiftLeft(j))
		b = b.Sub(c.shiftLeft(j))
	}

	return b, nil
}

func (el *FieldElement) TryDiv(e *FieldElement) (*FieldElement, error) {
	eInv, err := e.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot invert element")
	}
	return el.Mul(eInv), nil
}

func (el *FieldElement) IsZero() bool {
	return (el[1] | el[0]) == 0
}

func (el *FieldElement) TryNeg() (*FieldElement, error) {
	return el.Neg(), nil
}

func (el *FieldElement) TrySub(e *FieldElement) (*FieldElement, error) {
	return el.Sub(e), nil
}

func (el *FieldElement) OpInv() *FieldElement {
	return el.Neg()
}

func (el *FieldElement) Neg() *FieldElement {
	return el.Clone()
}

func (el *FieldElement) Sub(e *FieldElement) *FieldElement {
	return el.Add(e)
}

func (*FieldElement) IsProbablyPrime() bool {
	return false
}

func (el *FieldElement) EuclideanDiv(rhs *FieldElement) (quot, rem *FieldElement, err error) {
	quot, err = el.TryDiv(rhs)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("division by zero")
	}
	return quot, NewField().Zero(), nil
}

func (el *FieldElement) EuclideanValuation() cardinal.Cardinal {
	if el.IsZero() {
		return cardinal.New(0)
	} else {
		return cardinal.New(1)
	}
}

func (*FieldElement) ComponentsBytes() [][]byte {
	panic("not implemented")
}

func (el *FieldElement) Add(y *FieldElement) *FieldElement {
	return &FieldElement{el[0] ^ y[0], el[1] ^ y[1]}
}

func (el *FieldElement) Mul(rhs *FieldElement) *FieldElement {
	// From section 2.3 of https://link.springer.com/book/10.1007/b97644, employing
	// the irreducible polynomial f(X) = X^128 + X^7 + X^2 + X + 1. (from Table A.1).
	var z [4]uint64
	var b = [3]uint64{rhs[0], rhs[1], 0}
	for k := range 64 {
		for j := range FieldElementLimbs {
			// conditionally add a copy of shifted B to C, depending on the appropriate bit of A
			mask := -(el[j] >> k & 0x01) // if A[j] >> k & 0x01 == 1 then 0xFFF... else 0x000...
			for i := range FieldElementLimbs + 1 {
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

func (el *FieldElement) shiftLeft(k int) *FieldElement {
	if k <= 0 {
		return el.Clone()
	}
	if k >= 128 {
		return &FieldElement{0, 0}
	}
	if k >= 64 {
		return &FieldElement{0, el[0] << (k - 64)}
	}
	return &FieldElement{el[0] << k, (el[1] << k) | (el[0] >> (64 - k))}
}

func (el *FieldElement) degree() int {
	z := bits.LeadingZeros64(el[1])
	if z == 64 {
		z += bits.LeadingZeros64(el[0])
	}

	d := 127 - z
	if d < 0 {
		return 0
	} else {
		return d
	}
}

var (
	ErrDivisionByZero = errs.New("division by zero")
	ErrInvalidLength  = errs.New("invalid length")
)
