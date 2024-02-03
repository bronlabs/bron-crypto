package newprzs

import (
	"gonum.org/v1/gonum/stat/combin"
)

func newSubSetsSet(n, size int) []int {
	subSets := make([]int, 0)
	combinations := combin.Combinations(n, size)
	for _, combination := range combinations {
		subSet := 0
		for _, c := range combination {
			subSet |= 1 << c
		}
		subSets = append(subSets, subSet)
	}

	return subSets
}

func subSetContains(subSet, i int) bool {
	return (subSet & (1 << i)) != 0
}
