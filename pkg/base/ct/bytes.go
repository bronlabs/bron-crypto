package ct

import "crypto/subtle"

// CompareBytes is the constant-time counterpart of bytes.Compare.
// Lexicographic: first differing byte decides; if one is a prefix,
// the shorter slice is smaller.
func CompareBytes[T ~[]byte](x, y T) (lt, eq, gt Bool) {
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
		lt |= less & mask
		gt |= greater & mask
		done |= less | greater
	}

	// If all bytes up to minLen are equal, the shorter slice is less
	// Check lengths in constant time
	xShorter := Less(lenX, lenY)
	yShorter := Less(lenY, lenX)
	allEqual := done ^ 1

	lt |= xShorter & allEqual
	gt |= yShorter & allEqual
	eq = Equal(lenX, lenY) & allEqual

	return lt, eq, gt
}

// XorBytes computes the bitwise XOR of two byte slices and stores the result in dst.
// Wraps subtle.XORBytes.
func XorBytes[T ~[]byte](dst, x, y T) int {
	return subtle.XORBytes(dst, x, y)
}

// AndBytes computes the bitwise AND of two byte slices and stores the result in dst.
func AndBytes[T ~[]byte](dst, x, y T) int {
	n := min(len(x), len(y))
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
func OrBytes[T ~[]byte](dst, x, y T) int {
	n := min(len(x), len(y))
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
