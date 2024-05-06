package testutils2

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/utils/randutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
)

type Generator[O Object] interface {
	Empty() O
	Prng() csprng.Seedable
}

type UnderlyingGenerator uint64

const MaxUnderlyer = UnderlyingGenerator(100)

func RandomUnderlyer(prng io.Reader, nonZero bool) (UnderlyingGenerator, error) {
	return randutils.RandomInteger[UnderlyingGenerator](prng, 0, MaxUnderlyer, nonZero)
}

func RandomUnderlyerSlice(prng io.Reader, size int, distinct, notAllZero, notAnyZero bool) ([]UnderlyingGenerator, error) {
	minSize := 0
	maxSize := MaxUnderlyer
	if size > 0 {
		minSize = size
		maxSize = UnderlyingGenerator(size)
	}
	return randutils.RandomSliceOfIntegers[[]UnderlyingGenerator](prng, minSize, int(maxSize), 0, MaxUnderlyer, distinct, notAllZero, notAnyZero)
}

func RandomInt(prng io.Reader, nonZero bool) (int, error) {
	return randutils.RandomInteger[int](prng, 0, int(MaxUnderlyer), nonZero)
}
