package sliceutils

import (
	"iter"
)

func Combinations[S ~[]T, T any](s S, k uint) iter.Seq[S] {
	if k > uint(len(s)) {
		return func(yield func(S) bool) {
			_ = yield(S{})
		}
	}

	return func(yield func(S) bool) {
		n := len(s)
		combinations := binomial(n, int(k))
		data := make([]int, k)
		for i := range data {
			data[i] = i
		}

		result := mapElements(s, data)
		if proceed := yield(result); !proceed {
			return
		}
		for i := 1; i < combinations; i++ {
			nextCombination(data, n, int(k))
			result := mapElements(s, data)
			if proceed := yield(result); !proceed {
				return
			}
		}
	}
}

func KCoveringCombinations[S ~[]T, T any](s S, k uint) iter.Seq[S] {
	return func(yield func(S) bool) {
		for i := k; i <= uint(len(s)); i++ {
			for comb := range Combinations(s, i) {
				if proceed := yield(comb); !proceed {
					return
				}
			}
		}
	}
}

func binomial(n, k int) int {
	// (n,k) = (n, n-k)
	if k > n/2 {
		k = n - k
	}
	b := 1
	for i := 1; i <= k; i++ {
		b = (n - k + i) * b / i
	}
	return b
}

func nextCombination(s []int, n, k int) {
	for j := k - 1; j >= 0; j-- {
		if s[j] == n+j-k {
			continue
		}
		s[j]++
		for l := j + 1; l < k; l++ {
			s[l] = s[j] + l - j
		}
		break
	}
}

func mapElements[S ~[]T, T any](input S, indices []int) []T {
	result := make(S, len(indices))
	for i, index := range indices {
		result[i] = input[index]
	}
	return result
}
