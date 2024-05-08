package testutils2

import (
	"bytes"
	"encoding/gob"
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/randutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"golang.org/x/crypto/sha3"
	"golang.org/x/exp/constraints"
)

type UnderlyerType = uint64

const MaxUnderlyerValue = UnderlyerType(100)

type AbstractAdapter[Underlyer, Type any] interface {
	Wrap(Underlyer) Type
	Unwrap(Type) Underlyer
	ZeroValue() Type
}

type Generator[T any] interface {
	Empty() T
	Prng() csprng.Seedable
	Reseed(seed []byte)
	Reconstruct(t *testing.T, fuzzerInput []byte) (output T, wasInCorpus bool)
}

type GeneratorTrait[U, T any] struct {
	prng    csprng.Seedable
	adapter AbstractAdapter[U, T]
}

func (g *GeneratorTrait[U, T]) Empty() T {
	return g.adapter.ZeroValue()
}

func (g *GeneratorTrait[U, T]) Prng() csprng.Seedable {
	return g.prng
}

func (g *GeneratorTrait[U, T]) Reseed(seed []byte) {
	if g.prng == nil {
		panic(errs.NewIsNil("prng"))
	}
	hashedSeed := sha3.Sum256(seed) // this is to make sure the fuzzer output matches chacha key size. Cutting off extra elements like seed[:32] may lose mutations and result in same seed in different fuzzers.
	out, err := g.prng.New(hashedSeed[:], []byte(prngSalt))
	if err != nil {
		panic(errs.WrapFailed(err, "could not derive a new prng with the provided seed"))
	}
	g.prng = out
}

func (g *GeneratorTrait[U, T]) Reconstruct(t *testing.T, fuzzerInput []byte) (output T, wasInCorpus bool) {
	t.Helper()
	if err := gob.NewDecoder(bytes.NewBuffer(fuzzerInput)).Decode(output); err != nil {
		g.Reseed(fuzzerInput)
		return output, false
	}
	return output, true
}

func RandomUnderlyer[T constraints.Integer](prng io.Reader, nonZero bool) (T, error) {
	return randutils.RandomInteger[T](prng, 0, T(MaxUnderlyerValue), nonZero)
}

func RandomUnderlyerSlice[S ~[]T, T constraints.Integer](prng io.Reader, size int, distinct, notAllZero, notAnyZero bool) (S, error) {
	minSize := 0
	maxSize := MaxUnderlyerValue
	if size > 0 {
		minSize = size
		maxSize = UnderlyerType(size)
	}
	return randutils.RandomSliceOfIntegers[S](prng, minSize, int(maxSize), 0, T(MaxUnderlyerValue), distinct, notAllZero, notAnyZero)
}

func RandomInt(prng io.Reader, nonZero bool) (int, error) {
	return randutils.RandomInteger[int](prng, 0, int(MaxUnderlyerValue), nonZero)
}
