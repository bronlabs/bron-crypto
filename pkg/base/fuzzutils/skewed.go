package fuzzutils

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type skewedObjectGenerator[O algebra.Object] struct {
	ObjectGenerator[O]
	zeroProbability int
}

// NewSkewedObjectGenerator returns a new ObjectGenerator that generates the zero
// object with the given percentual probability (0-100), and the non-zero object
// with the remaining probability. A negative zeroProbability will set it to a
// default of 5%.
func NewSkewedObjectGenerator[O algebra.Object](elementGenerator ObjectGenerator[O], zeroProbability int) ObjectGenerator[O] {
	if zeroProbability < 0 || zeroProbability > 100 {
		zeroProbability = 5
	}
	return skewedObjectGenerator[O]{
		ObjectGenerator: elementGenerator.Clone(),
		zeroProbability: zeroProbability,
	}
}

func (sog skewedObjectGenerator[O]) Generate() O {
	if sog.Prng().IntRange(0, 100) < sog.zeroProbability {
		return sog.Empty()
	}
	return sog.ObjectGenerator.Generate()
}
