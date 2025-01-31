package newimpl

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	"io"
)

var (
	_ fields.PrimeField[*Fps] = (*Fps)(nil)
)

type Fps struct {
	v fiatFpsTightFieldElement
}

func (f *Fps) Set(v *Fps) {
	f.v = v.v
}

func (f *Fps) SetZero() {
	f.v = fiatFpsTightFieldElement{}
}

func (f *Fps) SetOne() {
	f.v = fiatFpsTightFieldElement{1}
}

func (f *Fps) Select(choice uint64, z, nz *Fps) {
	fiatFpsSelectznz((*[5]uint64)(&f.v), fiatFpsUint1(choice), (*[5]uint64)(&z.v), (*[5]uint64)(&nz.v))
}

func (f *Fps) Add(lhs, rhs *Fps) {
	fiatFpsCarryAdd(&f.v, &lhs.v, &rhs.v)
}

func (f *Fps) Sub(lhs, rhs *Fps) {
	fiatFpsCarrySub(&f.v, &lhs.v, &rhs.v)
}

func (f *Fps) Neg(v *Fps) {
	fiatFpsCarryOpp(&f.v, &v.v)
}

func (f *Fps) Mul(lhs, rhs *Fps) {
	fiatFpsCarryMul(&f.v, (*fiatFpsLooseFieldElement)(&lhs.v), (*fiatFpsLooseFieldElement)(&rhs.v))
}

func (f *Fps) Square(v *Fps) {
	fiatFpsCarrySquare(&f.v, (*fiatFpsLooseFieldElement)(&v.v))
}

func (f *Fps) Inv(v *Fps) (ok uint64) {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) Div(lhs, rhs *Fps) (ok uint64) {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) Sqrt(v *Fps) (ok uint64) {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) Equals(rhs *Fps) uint64 {
	var diff fiatFpsTightFieldElement
	fiatFpsCarrySub(&diff, &f.v, &rhs.v)
	var diffBytes [32]byte
	fiatFpsToBytes(&diffBytes, &diff)
}

func (f *Fps) IsNonZero() uint64 {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) IsZero() uint64 {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) IsOne() uint64 {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) SetUniformBytes(componentsData ...[]byte) (ok uint64) {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) SetRandom(prng io.Reader) (ok uint64) {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) ComponentsBytes() [][]byte {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) Degree() uint64 {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) SetUint64(u uint64) {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) SetLimbs(data []uint64) (ok uint64) {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) SetBytes(data []byte) (ok uint64) {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) SetBytesWide(data []byte) (ok uint64) {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) Bytes() []byte {
	//TODO implement me
	panic("implement me")
}

func (f *Fps) Limbs() []uint64 {
	//TODO implement me
	panic("implement me")
}

func fpsAllZeros(data *[32]byte) (ok uint64) {
	v := uint64(
		data[0] | data[1] | data[2] | data[3] | data[4] | data[5] | data[6] | data[7] |
		data[8] | data[9] | data[10] | data[11] | data[12] | data[13] | data[14] | data[15] |
		data[16] | data[17] | data[18] | data[19] | data[20] | data[21] | data[22] | data[23] |
		data[24] | data[25] | data[26] | data[27] | data[28] | data[29] | data[30] | data[31]
	)

}