package bitstring

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/exp/constraints"

	"github.com/copperexchange/krypton-primitives/pkg/base/utils/itertools"
)

// ReverseBytes reverses the order of the bytes in a new slice.
func ReverseBytes(inBytes []byte) []byte {
	return itertools.Reverse(inBytes)
}

// PadToLeft pads the input bytes to the left with padLen zeroed bytes.
func PadToLeft(inBytes []byte, padLen int) []byte {
	if padLen < 0 {
		return inBytes
	}
	outBytes := make([]byte, padLen+len(inBytes))
	copy(outBytes[padLen:], inBytes)
	return outBytes
}

func ToBytes32LE(i int32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(i))
	return b
}

// PadToRight pads the input bytes to the right with padLen zeroed bytes.
// TODO: add pad argument
func PadToRight(inBytes []byte, padLen int) []byte {
	if padLen < 0 {
		return inBytes
	}
	outBytes := make([]byte, len(inBytes)+padLen)
	copy(outBytes[:len(outBytes)-padLen], inBytes)
	return outBytes
}

func TruncateWithEllipsis(text string, maxLen uint) string {
	if len(text) > int(maxLen) {
		return text[:maxLen] + fmt.Sprintf("...(%d)", len(text)-int(maxLen))
	}
	return text
}

// MemClr clears a byte slice. Compiles to `memclr` (https://github.com/golang/go/issues/5373).
func MemClr[S ~[]T, T constraints.Integer](dst S) {
	for i := range dst {
		dst[i] = 0
	}
}
