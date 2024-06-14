package internal

func FpCMove(out1 *FpTightFieldElement, arg1 uint64, arg2 *FpTightFieldElement, arg3 *FpTightFieldElement) {
	FpSelectznz((*[3]uint64)(out1), fpUint1(arg1), (*[3]uint64)(arg2), (*[3]uint64)(arg3))
}

func FpEqual(out *uint64, lhs, rhs *FpTightFieldElement) {
	var lhsBytes, rhsBytes [16]byte
	FpToBytes(&lhsBytes, lhs)
	FpToBytes(&rhsBytes, rhs)
	t := uint64(0)
	for i := range 16 {
		t |= uint64(lhsBytes[i]) ^ uint64(rhsBytes[i])
	}

	*out = ((t | -t) >> 63) ^ 1
}

func FpNonZero(out *uint64, in *FpTightFieldElement) {
	var bytes [16]byte
	FpToBytes(&bytes, in)
	t := uint64(0)
	for i := range 16 {
		t |= uint64(bytes[i])
	}
	*out = (t | -t) >> 63
}

func FpInv(out *FpTightFieldElement, in *FpTightFieldElement) {
	var result = FpTightFieldElement{1}
	var looseIn, looseResult FpLooseFieldElement
	FpRelax(&looseIn, in)

	for range 125 {
		FpRelax(&looseResult, &result)
		FpCarrySquare(&result, &looseResult)
		FpRelax(&looseResult, &result)
		FpCarryMul(&result, &looseResult, &looseIn)
	}

	FpRelax(&looseResult, &result)
	FpCarrySquare(&result, &looseResult)
	FpRelax(&looseResult, &result)
	FpCarrySquare(&result, &looseResult)
	FpRelax(&looseResult, &result)
	FpCarryMul(&result, &looseResult, &looseIn)

	inverted := uint64(0)
	FpNonZero(&inverted, in)
	FpSelectznz((*[3]uint64)(out), fpUint1(inverted), (*[3]uint64)(out), (*[3]uint64)(&result))
}

func FpCmp(out *int64, lhs, rhs *FpTightFieldElement) {
	var lhsBytes, rhsBytes [16]byte

	FpToBytes(&lhsBytes, lhs)
	FpToBytes(&rhsBytes, rhs)

	gt := uint64(0)
	lt := uint64(0)
	for i := 16 - 1; i >= 0; i-- {
		r := uint64(rhsBytes[i])
		l := uint64(lhsBytes[i])
		gt |= (r - l) >> 8 & 1 &^ lt
		lt |= (l - r) >> 8 & 1 &^ gt
	}

	*out = int64(gt) - int64(lt)
}
