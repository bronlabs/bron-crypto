package generators

import (
	"golang.org/x/exp/constraints"
	randv2 "math/rand/v2"
)

type stringGenerator struct {
	byteSliceGen Generator[[]byte]
}

func NewStringGenerator[L constraints.Unsigned](lenGen Generator[L], prng randv2.Source) Generator[string] {
	return &stringGenerator{
		byteSliceGen: NewSliceGenerator(lenGen, NewIntegerGenerator[byte](prng)),
	}
}

func (s *stringGenerator) Generate() string {
	return string(s.byteSliceGen.Generate())
}
