package ct

import "golang.org/x/exp/constraints"

func IsZero[I constraints.Integer](x I) Choice {
	xx := uint64(x)
	return Choice(((xx | -xx) >> 63) ^ 1)
}

// Equal returns 1 if x == y and 0 otherwise. Based on the subtle package.
func Equal[I constraints.Unsigned](x, y I) Choice {
	return IsZero(x ^ y)
}

// Greater returns 1 if x > y and 0 otherwise.
//
//   - If both x < 2^63 and y < 2^63, then y-x will have its high bit set only if x > y.
//   - If either x >= 2^63 or y >= 2^63 (but not both), then the result is the high bit of x.
//   - If both x >= 2^63 and y >= 2^63, then we can virtually subtract 2^63 from both,
//     and we are back to the first case. Since (y-2^63)-(x-2^63) = y-x, the direct subtraction is already fine.
func Greater[I constraints.Unsigned](x, y I) Choice {
	xx := uint64(x)
	yy := uint64(y)
	zz := yy - xx
	return Choice((zz ^ ((xx ^ yy) & (xx ^ zz))) >> 63)
}

// Less returns 1 if x < y and 0 otherwise.
func Less[I constraints.Unsigned](x, y I) Choice {
	return Greater(y, x)
}

// LessOrEqual returns 1 if x <= y and 0 otherwise.
func LessOrEqual[I constraints.Unsigned](x, y I) Choice {
	return Greater(x, y) ^ 1
}

// GreaterOrEqual returns 1 if x >= y and 0 otherwise.
func GreaterOrEqual[I constraints.Unsigned](x, y I) Choice {
	return Greater(y, x) ^ 1
}

func Cmp[I constraints.Integer](x, y I) (lt, eq, gt Bool) {
	ux := uint64(x)
	uy := uint64(y)

	// Equal: 1 if x == y, else 0
	eq = Bool(Equal(ux, uy))

	// Greater: 1 if x > y, else 0
	gt = Bool(Greater(ux, uy))

	// Less: 1 if x < y, else 0
	lt = Bool(Greater(uy, ux))
	return
}

// Select returns x0 if choice == 0 and x1 if choice == 1. Undefined for other values of choice.
// It supports both signed and unsigned integer types.
func Select[I constraints.Integer](choice Choice, x0, x1 I) I {
	mask := I(-int64(choice)) // 0 if choice == 0, -1 (all bits 1) if choice == 1
	return (x0 &^ mask) | (x1 & mask)
}
