package internal

func FqCMove(out1 *[4]uint64, arg1 uint64, arg2 *[4]uint64, arg3 *[4]uint64) {
	FqSelectznz(out1, fqUint1(arg1), arg2, arg3)
}

func FqCmpLimbs(out *int64, l, r *[4]uint64) {
	gt := uint64(0)
	lt := uint64(0)
	for i := 4 - 1; i >= 0; i-- {
		// convert to two 64-bit numbers where
		// the leading bits are zeros and hold no meaning
		//  so rhs - f actually means gt
		// and f - rhs actually means lt.
		rhsH := r[i] >> 32
		rhsL := r[i] & 0xffffffff
		lhsH := l[i] >> 32
		lhsL := l[i] & 0xffffffff

		// Check the leading bit
		// if negative then f > rhs
		// if positive then f < rhs
		gt |= (rhsH - lhsH) >> 32 & 1 &^ lt
		lt |= (lhsH - rhsH) >> 32 & 1 &^ gt
		gt |= (rhsL - lhsL) >> 32 & 1 &^ lt
		lt |= (lhsL - rhsL) >> 32 & 1 &^ gt
	}

	// Make the result -1 for <, 0 for =, 1 for >
	*out = int64(gt) - int64(lt)
}
