package impl

import (
	"encoding/binary"
	"io"
	"math/big"

	filippoField "filippo.io/edwards25519/field"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
)

var _ fields.PrimeField[*Fp] = (*Fp)(nil)

type Fp struct {
	V filippoField.Element
}

func (f *Fp) Set(v *Fp) {
	f.V.Set(&v.V)
}

func (f *Fp) SetZero() {
	f.V.Zero()
}

func (f *Fp) SetOne() {
	f.V.One()
}

func (f *Fp) SetUniformBytes(componentsData ...[]byte) (ok uint64) {
	if len(componentsData) != 1 {
		return 0
	}

	return f.SetBytesWide(componentsData[0])
}

func (f *Fp) SetRandom(prng io.Reader) (ok uint64) {
	var data [64]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return 0
	}

	_, err = f.V.SetWideBytes(data[:])
	if err != nil {
		return 0
	}

	return 1
}

func (f *Fp) Select(choice uint64, z, nz *Fp) {
	// yes, the condition is reversed comparing to others
	f.V.Select(&nz.V, &z.V, int(choice))
}

func (f *Fp) Add(lhs, rhs *Fp) {
	f.V.Add(&lhs.V, &rhs.V)
}

func (f *Fp) Sub(lhs, rhs *Fp) {
	f.V.Subtract(&lhs.V, &rhs.V)
}

func (f *Fp) Neg(v *Fp) {
	f.V.Negate(&v.V)
}

func (f *Fp) Mul(lhs, rhs *Fp) {
	f.V.Multiply(&lhs.V, &rhs.V)
}

func (f *Fp) Square(v *Fp) {
	f.V.Square(&v.V)
}

func (f *Fp) Inv(v *Fp) (ok uint64) {
	var zero, inv filippoField.Element
	zero.Zero()
	inv.Invert(&v.V)
	wasInverted := inv.Equal(&zero) ^ 1

	f.V.Select(&inv, &f.V, wasInverted)
	return uint64(wasInverted)
}

func (f *Fp) Div(lhs, rhs *Fp) (ok uint64) {
	var zero, rhsInv, result filippoField.Element
	zero.Zero()
	rhsInv.Invert(&rhs.V)
	wasInverted := rhsInv.Equal(&zero) ^ 1
	result.Multiply(&lhs.V, &rhsInv)

	f.V.Select(&result, &f.V, wasInverted)
	return uint64(wasInverted)
}

func (f *Fp) Sqrt(v *Fp) (ok uint64) {
	var result, one filippoField.Element
	one.One()
	_, wasSquare := result.SqrtRatio(&v.V, &one)

	f.V.Select(&result, &f.V, wasSquare)
	return uint64(wasSquare)
}

func (f *Fp) IsNonZero() uint64 {
	var zero filippoField.Element
	return uint64(f.V.Equal(zero.Zero()) ^ 1)
}

func (f *Fp) IsZero() uint64 {
	var zero filippoField.Element
	return uint64(f.V.Equal(zero.Zero()))
}

func (f *Fp) IsOne() uint64 {
	var one filippoField.Element
	return uint64(f.V.Equal(one.One()))
}

func (f *Fp) Equals(rhs *Fp) uint64 {
	return uint64(f.V.Equal(&rhs.V))
}

func (f *Fp) ComponentsBytes() [][]byte {
	data := f.V.Bytes()
	return [][]byte{data}
}

func (*Fp) Degree() uint64 {
	return 1
}

func (f *Fp) SetUint64(u uint64) {
	var data [32]byte
	binary.LittleEndian.PutUint64(data[:8], u)
	_, err := f.V.SetBytes(data[:])
	if err != nil {
		panic("this should never happen")
	}
}

func (f *Fp) SetLimbs(data []uint64) (ok uint64) {
	b := make([]byte, len(data)*8)
	for i, l := range data {
		binary.LittleEndian.PutUint64(b[i*8:(i+1)*8], l)
	}

	return f.SetBytes(b)
}

func (f *Fp) SetBytes(data []byte) (ok uint64) {
	_, err := f.V.SetBytes(data)
	if err != nil {
		return 0
	}

	return 1
}

func (f *Fp) SetBytesWide(data []byte) (ok uint64) {
	if len(data) > 64 {
		return 0
	}

	var wideData [64]byte
	copy(wideData[:], data)
	_, err := f.V.SetWideBytes(wideData[:])
	if err != nil {
		return 0
	}

	return 1
}

func (f *Fp) Bytes() []byte {
	return f.V.Bytes()
}

func (*Fp) Limbs() []uint64 {
	//TODO implement me
	panic("not implemented")
}

func (f *Fp) MustSetHex(hexString string) {
	bi, ok := new(big.Int).SetString(hexString, 16)
	if !ok {
		panic("invalid hex string")
	}

	var biBytes [32]byte
	copy(biBytes[:], bi.Bytes())
	_, err := f.V.SetBytes(biBytes[:])
	if err != nil {
		panic(err)
	}
}
