package combinatorics

import (
	"golang.org/x/exp/constraints"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Product[T, U any] struct {
	First  T
	Second U
}

func BinomialCoefficient(n, k uint) (uint, error) {
	if n < k {
		return 0, errs.NewValue("n < k")
	}
	// (n,k) = (n, n-k)
	if k > n/2 {
		k = n - k
	}
	b := uint(1)
	for i := uint(1); i <= k; i++ {
		b = (n - k + i) * b / i
	}
	return b, nil
}

func Factorial(n uint) uint {
	out := uint(1)
	for i := uint(2); i <= n; i++ {
		out *= i
	}
	return out
}

func SubFactorial(n uint) uint {
	memo := map[uint]uint{0: 1, 1: 0}
	var wrapper = func(x uint) uint {
		if out, exists := memo[x]; exists {
			return out
		}
		memo[x] = (x - 1) * (SubFactorial(x-1) + SubFactorial(x-2))
		return memo[x]
	}
	return wrapper(n)
}

func mapIndicesToElements[T any, I constraints.Integer](input *[]T, indices []I) []T {
	result := make([]T, len(indices))
	for i, index := range indices {
		result[i] = (*input)[index]
	}
	return result
}
