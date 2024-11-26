package combinatorics

import (
	crand "crypto/rand"
	"io"
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
)

var TotalPermutations = Factorial

func PermutationsGenerator[T any](input *[]T) <-chan []T {
	if input == nil {
		panic(errs.NewIsNil("input"))
	}
	ch := make(chan []T, 1)
	go func() {
		defer close(ch)
		n := uint(len(*input))
		for p := range PartialPermutationsGenerator(input, n) {
			ch <- p
		}
	}()
	return ch
}

func Permutations[T any](input []T) [][]T {
	n := uint(len(input))
	if n == 0 {
		return [][]T{}
	}
	out := make([][]T, TotalPermutations(n))
	i := 0
	for p := range PermutationsGenerator(&input) {
		out[i] = p
		i++
	}
	return out
}

// Shuffle uses Fisher-Yates algorithm to produce a random permutation of the input.
// https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm
func Shuffle[T any](input []T, prng io.Reader) ([]T, error) {
	if input == nil {
		return nil, errs.NewIsNil("input")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	n := len(input)
	if n == 0 {
		return []T{}, nil
	}

	out := make([]T, len(input))
	copy(out, input)

	for i := n - 1; i >= 1; i-- {
		jBig, err := crand.Int(prng, new(big.Int).SetUint64(uint64(i)))
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not produce random sample from [0, ..., %d]", i)
		}
		j := jBig.Uint64() // i <= n <= Max(int) < Max(uint64), since n := len(input) whose type is int
		out[j], out[i] = out[i], out[j]
	}
	return out, nil
}

func TotalPartialPermutations(n, k uint) (uint, error) {
	if n < k {
		return 0, errs.NewValue("n < k")
	}

	out := uint(1)
	for i := n - k + 1; i <= n; i++ {
		out *= i
	}
	return out, nil
}

// https://cs.stackexchange.com/a/133678
func PartialPermutationsGenerator[T any](input *[]T, k uint) <-chan []T {
	if input == nil {
		panic(errs.NewIsNil("input"))
	}
	n := len(*input)
	A := make([]bool, n)
	for i := range k {
		A[i] = true
	}
	L := make([]int, k)
	for i := range k {
		L[i] = safecast.MustToInt(i)
	}

	ch := make(chan []T, 1)
	go func() {
		defer close(ch)

		ch <- mapIndicesToElements(input, L)

		for {
			j := safecast.MustToInt(k) - 1
			for j >= 0 {
				A[L[j]] = false
				t := L[j] + 1
				for t < n && A[t] {
					t++
				}
				if t < n {
					A[t] = true
					L[j] = t
					r := 0
					j++
					for j < safecast.MustToInt(k) {
						for A[r] {
							r++
						}
						A[r] = true
						L[j] = r
						j++
					}
					ch <- mapIndicesToElements(input, L)
					break
				}
				j--
			}
			if j == -1 {
				return
			}
		}
	}()
	return ch
}

func PartialPermutations[T any](input []T, k uint) ([][]T, error) {
	total, err := TotalPartialPermutations(uint(len(input)), k)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute total partial nPk")
	}
	out := make([][]T, total)
	if total == 0 {
		return out, nil
	}
	i := 0
	for p := range PartialPermutationsGenerator(&input, k) {
		out[i] = p
		i++
	}
	return out, nil
}

func IsFixedPoint[T any](input, permutation *[]T, isEqual func(x, y T) bool) bool {
	if input == nil || permutation == nil || len(*input) != len(*permutation) {
		return false
	}
	isFixedPoint := true
	for i, x := range *input {
		if !isEqual(x, (*permutation)[i]) {
			isFixedPoint = false
			break
		}
	}
	return isFixedPoint
}
