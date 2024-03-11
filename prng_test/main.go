package main

import (
	"github.com/copperexchange/prng-tester/prngs"
	"os"
)

func main() {
	if len(os.Args) == 1 || os.Args[1] == "crand" {
		RunPrngTest(&prngs.CrandPrngTest{})
	} else {
		panic("unknown prng")
	}
}
