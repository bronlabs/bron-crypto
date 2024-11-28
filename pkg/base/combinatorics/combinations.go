package combinatorics

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
)

var TotalCombinations = BinomialCoefficient

// https://github.com/gonum/gonum/blob/d532ec56a8f2d219667a693e08dd209afd9b8d0a/stat/combin/combin.go#L155
func CombinationGenerator[T any](input *[]T, k uint) <-chan []T {
	if input == nil {
		panic(errs.NewIsNil("input"))
	}
	n := uint(len(*input))
	totalCombinations, err := BinomialCoefficient(n, k)
	if err != nil {
		panic(errs.WrapFailed(err, "could not compute C(n, k)"))
	}
	ch := make(chan []T, 1)
	go func() {
		defer close(ch)
		if totalCombinations == 0 {
			return
		}
		current := make([]uint, k)
		for i := range k {
			current[i] = i
		}
		ch <- mapIndicesToElements(input, current)
		for i := uint(1); i < totalCombinations; i++ {
			next := make([]uint, k)
			copy(next, current)

			for j := safecast.ToInt(k - 1); j >= 0; j-- {
				if next[j] == n+safecast.ToUint(j)-k {
					continue
				}
				next[j]++
				for l := safecast.ToUint(j + 1); l < k; l++ {
					next[l] = next[j] + l - safecast.ToUint(j)
				}
				break
			}

			current = next
			ch <- mapIndicesToElements(input, current)
		}
	}()
	return ch
}

func Combinations[T any](input []T, k uint) ([][]T, error) {
	totalCombinations, err := BinomialCoefficient(uint(len(input)), k)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute C(n, k)")
	}
	results := make([][]T, totalCombinations)
	i := 0
	for c := range CombinationGenerator(&input, k) {
		results[i] = c
		i++
	}
	return results, nil
}
