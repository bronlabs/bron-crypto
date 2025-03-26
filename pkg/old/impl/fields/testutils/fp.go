package testutils

import (
	_ "embed"
	"encoding/binary"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	"io"
	"math/bits"
)

const TestFpModulus = 0x429d16a1

var (
	_ fields.PrimeField[*TestFp] = (*TestFp)(nil)

	TestFpE             = uint64(bits.TrailingZeros64(uint64(TestFpModulus) - 1))
	TestFpProgenitorExp = binary.LittleEndian.AppendUint32(nil, TestFpModulus>>(TestFpE+1))
	TestFpRootOfUnity   = uint64(0xa93059e)
)

type TestFp uint64

func (fp *TestFp) Set(v *TestFp) {
	*fp = *v
}

func (fp *TestFp) SetZero() {
	*fp = 0
}

func (fp *TestFp) SetOne() {
	*fp = 1
}

func (fp *TestFp) SetUniformBytes(componentsData ...[]byte) (ok uint64) {
	if len(componentsData) != 1 {
		return 0
	}

	fp.SetBytesWide(componentsData[0])
	return 1
}

func (fp *TestFp) SetRandom(prng io.Reader) (ok uint64) {
	if prng == nil {
		return 0
	}

	var data [8]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return 0
	}

	*fp = TestFp(binary.LittleEndian.Uint64(data[:]) % TestFpModulus)
	return 1
}

func (fp *TestFp) Select(choice uint64, z, nz *TestFp) {
	switch choice {
	case 0:
		*fp = *z
		return
	case 1:
		*fp = *nz
		return
	}

	panic("invalid choice")
}

func (fp *TestFp) Add(lhs, rhs *TestFp) {
	*fp = (*lhs + *rhs) % TestFpModulus
}

func (fp *TestFp) Sub(lhs, rhs *TestFp) {
	*fp = (TestFpModulus + *lhs - *rhs) % TestFpModulus
}

func (fp *TestFp) Neg(v *TestFp) {
	*fp = (TestFpModulus - *v) % TestFpModulus
}

func (fp *TestFp) Mul(lhs, rhs *TestFp) {
	*fp = (*lhs * *rhs) % TestFpModulus
}

func (fp *TestFp) Square(v *TestFp) {
	*fp = (*v * *v) % TestFpModulus
}

func (fp *TestFp) Inv(v *TestFp) (ok uint64) {
	if *v == 0 {
		return 0
	}

	var vInv TestFp
	fields.Pow(&vInv, v, binary.LittleEndian.AppendUint64(nil, TestFpModulus-2))

	var sanityCheck TestFp
	sanityCheck.Mul(&vInv, v)
	if sanityCheck.IsOne() != 1 {
		panic("sanity check failed")
	}

	*fp = vInv
	return 1
}

func (fp *TestFp) Div(lhs, rhs *TestFp) (ok uint64) {
	if *rhs == 0 {
		return 0
	}

	var rhsInv TestFp
	fields.Pow(&rhsInv, rhs, binary.LittleEndian.AppendUint64(nil, TestFpModulus-2))
	*fp = (*lhs * rhsInv) % TestFpModulus
	return 1
}

func (fp *TestFp) Sqrt(v *TestFp) (ok uint64) {
	var trait fields.SqrtTrait[*TestFp, TestFp]
	return trait.Sqrt(fp, v, (*TestFp)(&TestFpRootOfUnity), TestFpE, TestFpProgenitorExp)
}

func (fp *TestFp) IsNonZero() uint64 {
	if *fp != 0 {
		return 1
	}

	return 0
}

func (fp *TestFp) IsZero() uint64 {
	if *fp == 0 {
		return 1
	}

	return 0
}

func (fp *TestFp) IsOne() uint64 {
	if *fp == 1 {
		return 1
	}

	return 0
}

func (fp *TestFp) Equals(rhs *TestFp) uint64 {
	if *fp == *rhs {
		return 1
	}

	return 0
}

func (fp *TestFp) ComponentsBytes() [][]byte {
	return [][]byte{fp.Bytes()}
}

func (fp *TestFp) SetUint64(u uint64) {
	*fp = TestFp(u % TestFpModulus)
}

func (fp *TestFp) SetLimbs(data []uint64) (ok uint64) {
	if len(data) != 1 || bits.Len64(data[0]) > 32 {
		return 0
	}

	*fp = TestFp(data[0] % TestFpModulus)
	return 1
}

func (fp *TestFp) SetBytes(data []byte) (ok uint64) {
	if len(data) != 4 {
		return 0
	}

	var wideData [8]byte
	copy(wideData[:], data)
	*fp = TestFp(binary.LittleEndian.Uint64(wideData[:]) % TestFpModulus)
	return 1
}

func (fp *TestFp) SetBytesWide(data []byte) (ok uint64) {
	if len(data) > 8 {
		return 0
	}

	var wideData [8]byte
	copy(wideData[:], data)
	*fp = TestFp(binary.LittleEndian.Uint64(wideData[:]) % TestFpModulus)
	return 1
}

func (fp *TestFp) Bytes() []byte {
	return binary.LittleEndian.AppendUint32(nil, uint32(*fp))
}

func (fp *TestFp) Limbs() []uint64 {
	return []uint64{uint64(*fp)}
}

func (fp *TestFp) Degree() uint64 {
	return 1
}
