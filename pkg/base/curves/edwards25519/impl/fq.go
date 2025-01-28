package impl

import (
	"encoding/binary"
	"io"
	"math/big"
	"slices"

	filippo "filippo.io/edwards25519"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
)

var (
	_ fields.PrimeField[*Fq] = (*Fq)(nil)

	FqRootOfUnity Fq
)

const (
	FqE         = 2
	FqBytes     = 32
	FqWideBytes = 64
)

//nolint:gochecknoinits // field params initialization
func init() {
	FqRootOfUnity.MustSet("0x94a7310e07981e77d3d6d60abc1c27a0ef0565342ce83febe8775dfebbe07d4")
}

type Fq struct {
	V filippo.Scalar
}

func (f *Fq) Set(v *Fq) {
	f.V.Set(&v.V)
}

func (f *Fq) SetZero() {
	zeroBytes := [32]byte{}
	_, err := f.V.SetCanonicalBytes(zeroBytes[:])
	if err != nil {
		panic("this should never happen")
	}
}

func (f *Fq) SetOne() {
	oneBytes := [32]byte{1}
	_, err := f.V.SetCanonicalBytes(oneBytes[:])
	if err != nil {
		panic("this should never happen")
	}
}

func (f *Fq) SetUniformBytes(componentsData ...[]byte) (ok uint64) {
	if len(componentsData) != 1 {
		return 0
	}

	return f.SetBytesWide(componentsData[0])
}

func (f *Fq) SetRandom(prng io.Reader) (ok uint64) {
	var data [64]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return 0
	}

	_, err = f.V.SetUniformBytes(data[:])
	if err != nil {
		return 0
	}

	return 1
}

func (f *Fq) Select(choice uint64, z, nz *Fq) {
	// yes, the condition is reversed comparing to others
	if choice == 0 {
		f.V.Set(&z.V)
	} else {
		f.V.Set(&nz.V)
	}
}

func (f *Fq) Add(lhs, rhs *Fq) {
	f.V.Add(&lhs.V, &rhs.V)
}

func (f *Fq) Sub(lhs, rhs *Fq) {
	f.V.Subtract(&lhs.V, &rhs.V)
}

func (f *Fq) Neg(v *Fq) {
	f.V.Negate(&v.V)
}

func (f *Fq) Mul(lhs, rhs *Fq) {
	f.V.Multiply(&lhs.V, &rhs.V)
}

func (f *Fq) Square(v *Fq) {
	f.V.Multiply(&v.V, &v.V)
}

func (f *Fq) Inv(v *Fq) (ok uint64) {
	var zero, inv filippo.Scalar
	inv.Invert(&v.V)
	wasInverted := inv.Equal(&zero) ^ 1

	f.V.Set(&inv)
	return uint64(wasInverted)
}

func (f *Fq) Div(lhs, rhs *Fq) (ok uint64) {
	var zero, rhsInv, result filippo.Scalar
	rhsInv.Invert(&rhs.V)
	wasInverted := rhsInv.Equal(&zero) ^ 1
	result.Multiply(&lhs.V, &rhsInv)

	f.V.Set(&result)
	return uint64(wasInverted)
}

func (f *Fq) Sqrt(v *Fq) (ok uint64) {
	e, _ := new(big.Int).SetString("0x2000000000000000000000000000000029bdf3bd45ef39acb024c634b9eba7d", 0)
	eBytes := e.Bytes()
	slices.Reverse(eBytes)

	var result Fq
	ok = fields.SqrtTrait[*Fq, Fq]{}.Sqrt(&result, v, &FqRootOfUnity, FqE, eBytes)
	f.Select(ok, f, &result)
	return ok
}

func (f *Fq) IsNonZero() uint64 {
	var zero filippo.Scalar
	return uint64(f.V.Equal(&zero) ^ 1)
}

func (f *Fq) IsZero() uint64 {
	var zero filippo.Scalar
	return uint64(f.V.Equal(&zero))
}

func (f *Fq) IsOne() uint64 {
	var one Fq
	one.SetOne()
	return uint64(f.V.Equal(&one.V))
}

func (f *Fq) Equals(rhs *Fq) uint64 {
	return uint64(f.V.Equal(&rhs.V))
}

func (f *Fq) ComponentsBytes() [][]byte {
	data := f.V.Bytes()
	return [][]byte{data}
}

func (*Fq) Degree() uint64 {
	return 1
}

func (f *Fq) SetUint64(u uint64) {
	var data [32]byte
	binary.LittleEndian.PutUint64(data[:8], u)
	_, err := f.V.SetCanonicalBytes(data[:])
	if err != nil {
		panic("this should never happen")
	}
}

func (f *Fq) SetLimbs(data []uint64) (ok uint64) {
	b := make([]byte, len(data)*8)
	for i, l := range data {
		binary.LittleEndian.PutUint64(b[i*8:(i+1)*8], l)
	}

	return f.SetBytesWide(b)
}

func (f *Fq) SetBytes(data []byte) (ok uint64) {
	_, err := f.V.SetCanonicalBytes(data)
	if err != nil {
		return 0
	}

	return 1
}

func (f *Fq) SetBytesWide(data []byte) (ok uint64) {
	if len(data) > 64 {
		return 0
	}

	var wideData [64]byte
	copy(wideData[:], data)
	_, err := f.V.SetUniformBytes(wideData[:])
	if err != nil {
		return 0
	}

	return 1
}

func (f *Fq) Bytes() []byte {
	return f.V.Bytes()
}

func (f *Fq) Limbs() []uint64 {
	var limbs [4]uint64
	b := f.V.Bytes()
	for i := range limbs {
		limbs[i] = binary.LittleEndian.Uint64(b[i*8 : (i+1)*8])
	}

	return limbs[:]
}

func (f *Fq) MustSet(number string) {
	bi, ok := new(big.Int).SetString(number, 0)
	if !ok {
		panic("invalid number")
	}

	biBytes := bi.Bytes()
	slices.Reverse(biBytes)
	ok2 := f.SetBytesWide(biBytes)
	if ok2 != 1 {
		panic("invalid number")
	}
}
