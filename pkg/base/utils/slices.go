package utils

// SliceReverse reverses the order of the elements in a new slice.
func SliceReverse[S ~[]T, T any](in S) S {
	out := make([]T, len(in))

	for i, j := 0, len(in)-1; j >= 0; i, j = i+1, j-1 {
		out[i] = in[j]
	}

	return out
}

func SlicePadLeft[S ~[]T, T any](in S, padLen int) S {
	outBytes := make([]T, padLen+len(in))
	copy(outBytes[padLen:], in)
	return outBytes
}

func SlicePadRight[S ~[]T, T any](in S, padLen int) S {
	outBytes := make([]T, len(in)+padLen)
	copy(outBytes[:len(outBytes)-padLen], in)
	return outBytes
}

// SliceFill sets all elements in the slice to the given value.
func SliceFill[S ~[]T, T any](slice S, value T) {
	for i := range slice {
		slice[i] = value
	}
}
