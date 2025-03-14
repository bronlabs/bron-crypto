package combinatorics

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var TotalDerangements = SubFactorial

func DerangementsGenerator[T any](input *[]T, isEqual func(x, y T) bool) <-chan []T {
	if input == nil {
		panic(errs.NewIsNil("input"))
	}
	ch := make(chan []T, 1)
	go func() {
		defer close(ch)
		for p := range PermutationsGenerator(input) {
			if IsDerangement(input, &p, isEqual) {
				ch <- p
			}
		}
	}()
	return ch
}

func Deragements[T any](input []T, isEqual func(x, y T) bool) [][]T {
	n := uint(len(input))
	if n == 0 {
		return [][]T{}
	}
	out := make([][]T, TotalDerangements(n))
	i := 0
	for p := range DerangementsGenerator(&input, isEqual) {
		out[i] = p
		i++
	}
	return out
}

func IsDerangement[T any](input, permutation *[]T, isEqual func(x, y T) bool) bool {
	if input == nil || permutation == nil || len(*input) != len(*permutation) {
		return false
	}
	isDerangement := true
	for i, x := range *input {
		if isEqual(x, (*permutation)[i]) {
			isDerangement = false
			break
		}
	}
	return isDerangement
}
