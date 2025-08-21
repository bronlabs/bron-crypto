package ct

import (
	"golang.org/x/exp/constraints"
)

// SliceEachEqual returns 1 if all values of s are equal to e and returns 0 otherwise. Based on the subtle package.
func SliceEachEqual[S ~[]I, I constraints.Integer](s S, e I) Choice {
	v := I(0)
	for i := range s {
		v |= s[i] ^ e
	}
	return IsZero(v)
}

// SliceEqual returns 1 if x == y.
func SliceEqual[S ~[]I, I constraints.Integer](x, y S) Choice {
	if len(x) != len(y) {
		panic("ct: slices have different lengths")
	}

	v := I(0)
	for i := range x {
		v |= x[i] ^ y[i]
	}
	return IsZero(v)
}

// SliceIsZero returns 1 if all values of s are equal to 0 and returns 0 otherwise. Based on the subtle package.
func SliceIsZero[S ~[]E, E constraints.Integer](s S) Choice {
	v := E(0)
	for _, e := range s {
		v |= e
	}
	return IsZero(v)
}

// BytesCompare is the constant-time counterpart of bytes.Compare.
// Lexicographic: first differing byte decides; if one is a prefix,
// the shorter slice is smaller.
func BytesCompare(x, y []byte) (lt, eq, gt Bool) {
	lenX := len(x)
	lenY := len(y)
	minLen := Min(lenX, lenY)
	maxLen := Max(lenX, lenY)
	
	// Pad both slices to maxLen for constant-time access
	px := make([]byte, maxLen)
	py := make([]byte, maxLen)
	copy(px, x)
	copy(py, y)
	
	// Compare byte by byte up to minLen
	var done Choice // becomes 1 after the first difference
	for i := range minLen {
		bx := px[i]
		by := py[i]
		
		less := LessU64(uint64(bx), uint64(by))
		greater := LessU64(uint64(by), uint64(bx))
		
		mask := done ^ 1
		lt |= Bool(less & mask)
		gt |= Bool(greater & mask)
		done |= less | greater
	}
	
	// If all bytes up to minLen are equal, the shorter slice is less
	// Check lengths in constant time
	xShorter := Less(lenX, lenY)
	yShorter := Less(lenY, lenX)
	allEqual := done ^ 1
	
	lt |= Bool(xShorter & allEqual)
	gt |= Bool(yShorter & allEqual)
	eq = Bool(Equal(lenX, lenY) & allEqual)
	
	return
}

