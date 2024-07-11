package main

import (
	"log"
	"math/big"
	"sort"
)

// Let us fullfill the Sort interface:
type Int64ToSort []int64

func (s Int64ToSort) Len() int { return len(s) }

func (s Int64ToSort) Less(i, j int) bool { return s[i] < s[j] }

func (s Int64ToSort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func percentile(x []int64, perc float64) int64 {
	val := int(perc * float64(len(x)))
	if len(x) <= val || 0 >= val {
		log.Fatalln("Error, percentile should be smaller than 1 and bigger than 0. Got:\n", val, len(x), perc)
	}
	sort.Sort(Int64ToSort(x))
	return x[val]
}

// fromBase16 returns a new Big.Int from an hexadecimal string, as found in the go crypto tests suite
func fromBase16(base16 string) *big.Int {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		panic("bad number: " + base16)
	}
	return i
}
