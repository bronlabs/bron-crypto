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

// type Structure any

// type StructuralFuzzTarget[S Structure] func(s S)

// type StructureFuzzArg = uint64

// type CorpusManager[S Structure] interface {
// 	Add(f *testing.F, s S)
// 	Reconstruct(f *testing.F, fuzzInputs []byte) (s S, wasInCorpus bool)
// }

// var _ CorpusManager[Structure] = (*GobCorpusManager[Structure])(nil)

// type GobCorpusManager[S Structure] struct {
// 	registered bool
// }

// func NewGobCorpusManager(f *testing.F, concreteTypes ...any) {
// 	f.Helper()
// 	for _, ty := range concreteTypes {
// 		gob.Register(ty)
// 	}
// }

// func (m *GobCorpusManager[S]) Add(f *testing.F, s S) {
// 	f.Helper()

// 	var buf bytes.Buffer

// 	err := gob.NewEncoder(&buf).Encode(s)
// 	require.NoError(f, err)

// 	f.Add(buf.Bytes())
// }
// func (m *GobCorpusManager[S]) Reconstruct(f *testing.F, fuzzInput []byte) (s S, wasInCorpus bool) {
// 	f.Helper()
// 	var decoded S
// 	// rand. cInt
// 	if len(fuzzInput) == 0 {
// 		return decoded, false
// 	}
// 	if err := gob.NewDecoder(bytes.NewBuffer(fuzzInput)).Decode(decoded); err != nil {
// 		return decoded, false
// 	}
// 	return decoded, true
// }

// type harness[S Structure] struct {
// 	manager CorpusManager[S]
// 	prng    csprng.Seedable
// }

// func (h *harness[S]) CorpusManager() CorpusManager[S] {
// 	return h.manager
// }

// func (h *harness[S]) Prng() csprng.Seedable {
// 	return h.prng
// }

// type FuzzHarness[S Structure] struct {
// 	harness[S]
// }

// // func (h *FuzzHarness[S]) Reconstruct(f *testing.F, fuzzInput []byte) (S, error) {
// // 	f.Helper()
// // 	out, wasInCorpus := h.CorpusManager().Reconstruct(f, fuzzInput)
// // 	if wasInCorpus {
// // 		return out, nil
// // 	}
// // }

// // type PropertyTestingHarness[S Structure] struct {
// // 	F FuzzHarness[S]
// // }

// // func (pt *PropertyTestingHarness[S]) CorpusManager() CorpusManager[S] {
// // }

// // func (pt *PropertyTestingHarness[S]) Reconstruct(f *testing.T, fuzzInput []byte) (S, error)

// // func (pt *PropertyTestingHarness[S]) Prng() csprng.Seedable

// // type X struct {
// // }
