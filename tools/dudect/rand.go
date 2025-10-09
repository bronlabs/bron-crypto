package dudect

import (
	"math/rand"
)

// Rand is a wrapper around math/rand.Rand for convenience
type Rand = rand.Rand

// NewRand creates a new random number generator with the given seed
func NewRand(seed int64) *Rand {
	return rand.New(rand.NewSource(seed))
}