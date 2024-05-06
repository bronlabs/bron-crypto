package testutils2

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"reflect"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/stretchr/testify/require"
)

const prngSalt = "KRYPTON_FUZZUTIL_PRNG_SALT-"

// https://pkg.go.dev/testing#F.Fuzz
func IsFuzzableType(x any) bool {
	switch reflect.TypeOf(x).Kind() {
	case reflect.Slice:
		if reflect.TypeOf(x).Elem().Kind() != reflect.Uint8 {
			return false
		}
		fallthrough
	case reflect.String, reflect.Bool, reflect.Float32, reflect.Float64, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

func NeedsStructuralDeserialization(x any) bool {
	_, ok := x.(PrngSeedFuzzArg)
	return ok
}

type Structure Object

type PrngSeedFuzzArg = uint64

func Reseed(prng csprng.Seedable, seed PrngSeedFuzzArg) (csprng.Seedable, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, seed)
	out, err := prng.New(b, []byte(prngSalt))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive a new prng with the provided seed")
	}
	return out, nil
}

type CorpusManager[S Structure] interface {
	Add(f *testing.F, xs ...any)
	Reconstruct(f *testing.F, fuzzInput []byte) (s S, wasInCorpus bool)
}

var _ CorpusManager[Structure] = (*GobCorpusManager[Structure])(nil)

type GobCorpusManager[S Structure] struct {
	registered bool
}

func NewGobCorpusManager[S Structure](f *testing.F, concreteTypes ...any) *GobCorpusManager[S] {
	f.Helper()
	for _, ty := range concreteTypes {
		gob.Register(ty)
	}
	return &GobCorpusManager[S]{
		registered: true,
	}

}

func (m *GobCorpusManager[S]) Add(f *testing.F, xs ...any) {
	f.Helper()
	out := make([]any, len(xs))
	for i, x := range xs {
		if !IsFuzzableType(x) {
			panic(errs.NewType("input index %d is not fuzzable", i))
		}
		out[i] = x
		if NeedsStructuralDeserialization(x) {
			var buf bytes.Buffer
			encoder := gob.NewEncoder(&buf)
			err := encoder.Encode(x)
			require.NoError(f, err)
			out[i] = buf
		}
	}
	f.Add(out)
}
func (m *GobCorpusManager[S]) Reconstruct(f *testing.F, fuzzInput []byte) (s S, wasInCorpus bool) {
	f.Helper()
	var decoded S
	if len(fuzzInput) == 0 {
		return decoded, false
	}
	if err := gob.NewDecoder(bytes.NewBuffer(fuzzInput)).Decode(decoded); err != nil {
		return decoded, false
	}
	return decoded, true
}

type harness[S Structure] struct {
	manager CorpusManager[S]
	prng    csprng.Seedable
}

type PropertyTestingHarness[S Structure] struct {
	h harness[S]
}

func (pt *PropertyTestingHarness[S]) CorpusManager() CorpusManager[S] {
	return pt.h.manager
}

func (pt *PropertyTestingHarness[S]) Add(f *testing.F, xs ...any) {
	pt.h.manager.Add(f, xs)
}

// func (pt *PropertyTestingHarness[S]) ReconstructOrReseed(f *testing.F, fuzzInput []byte) (S, bool) {
// 	f.Helper()
// 	out, wasInCorpus := pt.CorpusManager().Reconstruct(f, fuzzInput)
// 	if wasInCorpus {
// 		return out, true
// 	}

// 	// Reseed(pt.Prng(), uint64(fuzzInput))
// }

func (pt *PropertyTestingHarness[S]) Prng() csprng.Seedable {
	return pt.h.prng
}
