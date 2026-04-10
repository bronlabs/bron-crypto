package ct

import "crypto/subtle"

// CompareBytes is the constant-time counterpart of bytes.Compare.
// Lexicographic: first differing byte decides; if one is a prefix,
// the shorter slice is smaller.
func CompareBytes[T ~[]byte](x, y T) (lt, eq, gt Bool) {
	lenX := len(x)
	lenY := len(y)
	maxLen := Max(lenX, lenY)

	// Pad both slices to maxLen so the loop always runs maxLen iterations,
	// avoiding a timing leak of min(len(x), len(y)).
	px := make([]byte, maxLen)
	py := make([]byte, maxLen)
	copy(px, x)
	copy(py, y)

	// Compare byte by byte over the full padded length
	var done Choice // becomes 1 after the first difference
	for i := range maxLen {
		bx := px[i]
		by := py[i]

		less := LessU64(uint64(bx), uint64(by))
		greater := LessU64(uint64(by), uint64(bx))

		mask := done ^ 1
		lt |= less & mask
		gt |= greater & mask
		done |= less | greater
	}

	// If all padded bytes were equal, the shorter slice is still less
	// (e.g., [1,2] < [1,2,0] even though the padded comparison found no difference).
	xShorter := Less(lenX, lenY)
	yShorter := Less(lenY, lenX)
	allEqual := done ^ 1

	lt |= xShorter & allEqual
	gt |= yShorter & allEqual
	eq = Equal(lenX, lenY) & allEqual

	return lt, eq, gt
}

// XorBytes computes the bitwise XOR of two byte slices and stores the result in dst.
// panics if dst is smaller than either x or y.
func XorBytes[T ~[]byte](dst, x, y T) int {
	return subtle.XORBytes(dst, x, y)
}

// AndBytes computes the bitwise AND of two byte slices and stores the result in dst.
// panics if x and y have different lengths or if dst is smaller than x.
func AndBytes[T ~[]byte](dst, x, y T) int {
	if len(x) != len(y) {
		panic("ct: slices have different lengths")
	}
	n := len(x)
	if n == 0 {
		return 0
	}
	if n > len(dst) {
		panic("dst too short")
	}
	for i := range n {
		dst[i] = x[i] & y[i]
	}
	return n
}

// OrBytes computes the bitwise OR of two byte slices and stores the result in dst.
// panics if x and y have different lengths or if dst is smaller than x.
func OrBytes[T ~[]byte](dst, x, y T) int {
	if len(x) != len(y) {
		panic("ct: slices have different lengths")
	}
	n := len(x)
	if n == 0 {
		return 0
	}
	if n > len(dst) {
		panic("dst too short")
	}
	for i := range n {
		dst[i] = x[i] | y[i]
	}
	return n
}

// NotBytes computes the bitwise NOT of a byte slice and stores the result in dst.
// panics if dst is smaller than x.
func NotBytes[T ~[]byte](dst, x T) int {
	n := len(x)
	if n == 0 {
		return 0
	}
	if n > len(dst) {
		panic("dst too short")
	}
	for i := range n {
		dst[i] = ^x[i]
	}
	return n
}
