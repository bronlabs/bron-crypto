package testutils

import (
	_ "embed"
	"encoding/binary"
	"io"
	"math/bits"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

const TestFpModulus = 0x429d16a1

var (
	_ impl.PrimeFieldElement[*TestFp] = (*TestFp)(nil)

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

func (fp *TestFp) SetUniformBytes(componentsData ...[]byte) (ok ct.Bool) {
	if len(componentsData) != 1 {
		return 0
	}

	fp.SetBytesWide(componentsData[0])
	return 1
}

func (fp *TestFp) SetRandom(prng io.Reader) (ok ct.Bool) {
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

func (fp *TestFp) CondAssign(choice ct.Choice, z, nz *TestFp) {
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

func (fp *TestFp) Double(v *TestFp) {
	*fp = (*v + *v) % TestFpModulus
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

func (fp *TestFp) Inv(v *TestFp) (ok ct.Bool) {
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

func (fp *TestFp) Div(lhs, rhs *TestFp) (ok ct.Bool) {
	if *rhs == 0 {
		return 0
	}

	var rhsInv TestFp
	fields.Pow(&rhsInv, rhs, binary.LittleEndian.AppendUint64(nil, TestFpModulus-2))
	*fp = (*lhs * rhsInv) % TestFpModulus
	return 1
}

func (fp *TestFp) Sqrt(v *TestFp) (ok ct.Bool) {
	return fields.TonelliShanks(fp, v, (*TestFp)(&TestFpRootOfUnity), TestFpE, TestFpProgenitorExp)
}

func (fp *TestFp) IsNonZero() ct.Bool {
	if *fp != 0 {
		return 1
	}

	return 0
}

func (fp *TestFp) IsZero() ct.Bool {
	if *fp == 0 {
		return 1
	}

	return 0
}

func (fp *TestFp) IsOne() ct.Bool {
	if *fp == 1 {
		return 1
	}

	return 0
}

func (fp *TestFp) Equal(rhs *TestFp) ct.Bool {
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

func (fp *TestFp) SetLimbs(data []uint64) (ok ct.Bool) {
	if len(data) != 1 || bits.Len64(data[0]) > 32 {
		return 0
	}

	*fp = TestFp(data[0] % TestFpModulus)
	return 1
}

func (fp *TestFp) SetBytes(data []byte) (ok ct.Bool) {
	if len(data) != 4 {
		return 0
	}

	var wideData [8]byte
	copy(wideData[:], data)
	*fp = TestFp(binary.LittleEndian.Uint64(wideData[:]) % TestFpModulus)
	return 1
}

func (fp *TestFp) SetBytesWide(data []byte) (ok ct.Bool) {
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
