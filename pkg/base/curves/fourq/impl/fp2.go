package impl

import "github.com/copperexchange/krypton-primitives/pkg/base/curves/fourq/impl/internal"

var (
	Fp2One = Fp2{Re: internal.FpTightFieldElement{1}}
	Fp2Eye = Fp2{Im: internal.FpTightFieldElement{1}}
)

type Fp2 struct {
	Re internal.FpTightFieldElement
	Im internal.FpTightFieldElement
}

func (e *Fp2) SetZero() *Fp2 {
	e.Re = internal.FpTightFieldElement{}
	e.Im = internal.FpTightFieldElement{}
	return e
}

func (e *Fp2) SetOne() *Fp2 {
	*e = Fp2One
	return e
}

func (e *Fp2) SetUint64(value uint64) *Fp2 {
	e.Re = internal.FpTightFieldElement{
		value & ((1 << 43) - 1), value >> 43,
	}
	e.Im = internal.FpTightFieldElement{}
	return e
}

func (e *Fp2) Add(lhs, rhs *Fp2) *Fp2 {
	internal.FpCarryAdd(&e.Re, &lhs.Re, &rhs.Re)
	internal.FpCarryAdd(&e.Im, &lhs.Im, &rhs.Im)
	return e
}

func (e *Fp2) Sub(lhs, rhs *Fp2) *Fp2 {
	internal.FpCarrySub(&e.Re, &lhs.Re, &rhs.Re)
	internal.FpCarrySub(&e.Im, &lhs.Im, &rhs.Im)
	return e
}

func (e *Fp2) Neg(x *Fp2) *Fp2 {
	internal.FpCarryOpp(&e.Re, &x.Re)
	internal.FpCarryOpp(&e.Im, &x.Im)
	return e
}

func (e *Fp2) Mul(lhs, rhs *Fp2) *Fp2 {
	var aPlusB, cPlusD, looseA, looseB, looseC, looseD internal.FpLooseFieldElement
	var ac, bd internal.FpTightFieldElement

	internal.FpAdd(&aPlusB, &lhs.Re, &lhs.Im)
	internal.FpAdd(&cPlusD, &rhs.Re, &rhs.Im)
	internal.FpRelax(&looseA, &lhs.Re)
	internal.FpRelax(&looseB, &lhs.Im)
	internal.FpRelax(&looseC, &rhs.Re)
	internal.FpRelax(&looseD, &rhs.Im)
	internal.FpCarryMul(&ac, &looseA, &looseC)
	internal.FpCarryMul(&bd, &looseB, &looseD)

	internal.FpCarrySub(&e.Re, &ac, &bd)
	internal.FpCarryMul(&e.Im, &aPlusB, &cPlusD)
	internal.FpCarrySub(&e.Im, &e.Im, &ac)
	internal.FpCarrySub(&e.Im, &e.Im, &bd)
	return e
}

func (e *Fp2) Square(x *Fp2) *Fp2 {
	var looseA, looseB, aPlusB, aMinusB internal.FpLooseFieldElement
	var ab internal.FpTightFieldElement

	internal.FpRelax(&looseA, &x.Re)
	internal.FpRelax(&looseB, &x.Im)
	internal.FpAdd(&aPlusB, &x.Re, &x.Im)
	internal.FpSub(&aMinusB, &x.Re, &x.Im)
	internal.FpCarryMul(&ab, &looseA, &looseB)

	internal.FpCarryMul(&e.Re, &aPlusB, &aMinusB)
	internal.FpCarryAdd(&e.Im, &ab, &ab)
	return e
}

func (e *Fp2) Inv(x *Fp2) (*Fp2, uint64) {
	var aLoose, bLoose, denomLoose internal.FpLooseFieldElement
	var aa, bb, aaPlusBb, denom, re, im internal.FpTightFieldElement
	var inverted = uint64(0)

	internal.FpRelax(&aLoose, &x.Re)
	internal.FpRelax(&bLoose, &x.Im)
	internal.FpCarrySquare(&aa, &aLoose)
	internal.FpCarrySquare(&bb, &bLoose)
	internal.FpCarryAdd(&aaPlusBb, &aa, &bb)
	internal.FpInv(&denom, &aaPlusBb)
	internal.FpNonZero(&inverted, &denom)
	internal.FpRelax(&denomLoose, &denom)
	internal.FpCarryMul(&re, &aLoose, &denomLoose)
	internal.FpCarryMul(&im, &bLoose, &denomLoose)
	internal.FpCarryOpp(&im, &im)
	internal.FpCMove(&e.Re, inverted, &e.Re, &re)
	internal.FpCMove(&e.Im, inverted, &e.Im, &im)
	return e, inverted
}

func (e *Fp2) Sqrt(x *Fp2) (*Fp2, uint64) {
	var alpha, alphaInc, x0, r0, r1, b, rr Fp2

	a1 := Fp2One
	for range 125 {
		a1.Square(&a1)
		a1.Mul(&a1, x)
	}
	alpha.Square(&a1)
	alpha.Mul(&alpha, x)

	x0.Mul(&a1, x)
	r0.Im = x0.Re
	internal.FpCarryOpp(&r0.Re, &x0.Im)
	rr.Square(&r0)
	wasSquare0 := rr.Equal(x)
	e.CMove(e, &rr, wasSquare0)

	alphaInc.Add(&alpha, &Fp2One)
	b = Fp2One
	for range 126 {
		b.Square(&b)
		b.Mul(&b, &alphaInc)
	}
	r1.Mul(&b, &x0)
	rr.Square(&r1)
	wasSquare1 := rr.Equal(x)
	e.CMove(e, &r1, wasSquare1)

	return e, wasSquare0 | wasSquare1
}

func (e *Fp2) Equal(y *Fp2) uint64 {
	var outRe, outIm uint64
	internal.FpEqual(&outRe, &e.Re, &y.Re)
	internal.FpEqual(&outIm, &e.Im, &y.Im)
	return outRe & outIm
}

func (e *Fp2) IsLexicographicallyGreater(rhs *Fp2) uint64 {
	var reOrder, imOrder int64
	internal.FpCmp(&reOrder, &e.Re, &rhs.Re)
	internal.FpCmp(&imOrder, &e.Im, &rhs.Im)

	reGreater := (((uint64(reOrder) ^ 1) | -(uint64(reOrder) ^ 1)) >> 63) ^ 1
	reEqual := ((uint64(reOrder) | -uint64(reOrder)) >> 63) ^ 1
	imGreater := (((uint64(imOrder) ^ 1) | -(uint64(imOrder) ^ 1)) >> 63) ^ 1

	return reGreater | (reEqual & imGreater)
}

func (e *Fp2) IsZero() uint64 {
	var reNonZero, imNonZero uint64
	internal.FpNonZero(&reNonZero, &e.Re)
	internal.FpNonZero(&imNonZero, &e.Im)
	return (reNonZero | imNonZero) ^ 1
}

func (e *Fp2) ToBytes() []byte {
	var buffer [32]byte
	internal.FpToBytes((*[16]uint8)(buffer[:16]), &e.Re)
	internal.FpToBytes((*[16]uint8)(buffer[16:]), &e.Im)
	return buffer[:]
}

func (e *Fp2) FromBytes(buffer []byte) *Fp2 {
	internal.FpFromBytes(&e.Re, (*[16]uint8)(buffer[0:16]))
	internal.FpFromBytes(&e.Im, (*[16]uint8)(buffer[16:32]))
	return e
}

func (e *Fp2) CMove(arg0, arg1 *Fp2, choice uint64) *Fp2 {
	internal.FpCMove(&e.Re, choice, &arg0.Re, &arg1.Re)
	internal.FpCMove(&e.Im, choice, &arg0.Im, &arg1.Im)
	return e
}
