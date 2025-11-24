package sliceutils

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// Combinations generates all k-combinations of the input slice s.
func Combinations[S ~[]T, T any](s S, k uint) iter.Seq[S] {
	if k > uint(len(s)) {
		return func(yield func(S) bool) {
			_ = yield(S{})
		}
	}

	return func(yield func(S) bool) {
		n := len(s)
		combinations := utils.Binomial(n, int(k))
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

// KCoveringCombinations generates all combinations of the input slice s with sizes from k to len(s).
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
