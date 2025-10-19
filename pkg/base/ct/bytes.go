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

	return lt, eq, gt
}

func XorBytes[T ~[]byte](dst, x, y T) int {
	return subtle.XORBytes(dst, x, y)
}

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

// TODO: remove
// PadLeft pads a byte slice with zeros on the left (for big-endian numbers) in constant time.
// The destination slice must have the target length.
// This is useful for big-endian integers where padding goes on the left.
func PadLeft[T ~[]byte](dst, src T) {
	dstLen := len(dst)
	srcLen := len(src)

	// Clear dst first
	for i := range dst {
		dst[i] = 0
	}

	// If src is empty or dst is empty, we're done
	if srcLen == 0 || dstLen == 0 {
		return
	}

	// Calculate how many bytes to copy
	copyLen := Min(srcLen, dstLen)

	// Calculate offsets
	dstOffset := Max(0, dstLen-srcLen)
	srcOffset := Max(0, srcLen-dstLen)

	// Copy the bytes
	for i := range copyLen {
		dst[dstOffset+i] = src[srcOffset+i]
	}
}
