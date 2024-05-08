package itertools

func NativeHashSet[T comparable](xs []T) map[T]any {
	h := map[T]any{}
	for _, x := range xs {
		h[x] = true
	}
	return h
}

func Contains[T comparable](xs []T, y T) bool {
	_, exists := NativeHashSet(xs)[y]
	return exists
}

func Unique[T comparable](xs []T) []T {
	h := NativeHashSet(xs)
	out := make([]T, len(h))
	i := 0
	for x := range h {
		out[i] = x
		i++
	}
	return out
}

func Filter[T comparable](xs []T, shouldKeep func(T) bool) []T {
	out := []T{}
	for _, x := range xs {
		if shouldKeep(x) {
			out = append(out, x)
		}
	}
	return out
}

func FilterOut[T comparable](xs []T, shouldNotKeep ...T) []T {
	h := NativeHashSet(shouldNotKeep)
	return Filter(xs, func(x T) bool {
		_, exists := h[x]
		return !exists
	})
}

func Product[T comparable](xs, ys []T) []T {
	out := make([]T, len(xs)+len(ys))
	for i, x := range xs {
		out[i] = x
	}
	for j, y := range ys {
		out[len(xs)+j] = y
	}
	return out
}

func ZipSmallest[T comparable](xs, ys []T) [][2]T {
	length := len(xs)
	if len(ys) < len(xs) {
		length = len(ys)
	}
	out := make([][2]T, length)
	for i := range length {
		out[i] = [2]T{xs[i], ys[i]}
	}
	return out
}

func Map[T comparable](xs []T, f func(x T) T) []T {
	out := make([]T, len(xs))
	for i, x := range xs {
		out[i] = f(x)
	}
	return out
}

func Reverse[T comparable](xs []T) []T {
	sx := make([]T, len(xs))
	for i, j := 0, len(xs)-1; j >= 0; i, j = i+1, j-1 {
		sx[i] = xs[j]
	}
	return sx
}

func Fold[T comparable](xs []T, f func(x, y T) T) T {
	if len(xs) == 0 {
		return *new(T)
	}
	out := xs[0]
	for _, x := range xs[1:] {
		out = f(out, x)
	}
	return out
}

func FoldRight[T comparable](xs []T, f func(x, y T) T) T {
	return Fold(Reverse(xs), f)
}
