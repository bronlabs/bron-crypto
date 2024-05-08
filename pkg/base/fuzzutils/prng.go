package fuzzutils

import (
	"encoding"
	"io"
	"math/rand/v2"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/randutils"
)

var _ io.Reader = (*PCG)(nil)
var _ rand.Source = (*PCG)(nil)
var _ encoding.BinaryMarshaler = (*PCG)(nil)
var _ encoding.BinaryUnmarshaler = (*PCG)(nil)

type PCG struct {
	lo, hi uint64
	src    *rand.PCG
	r      *rand.Rand
}

func (p *PCG) Seed(seed1, seed2 uint64) {
	p.lo = seed1
	p.hi = seed2
	p.src.Seed(seed1, seed2)
}

func (p *PCG) MarshalBinary() ([]byte, error) {
	return p.src.MarshalBinary()
}

func (p *PCG) UnmarshalBinary(data []byte) error {
	return p.src.UnmarshalBinary(data)
}

func (p *PCG) Uint64() uint64 {
	return p.src.Uint64()
}

func (p *PCG) Rand() *rand.Rand {
	return p.r
}

func (p *PCG) Read(b []byte) (n int, err error) {
	r := p.Rand()
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	return len(b), nil
}

type Prng struct {
	PCG
	MaxUnderlyer Underlyer
}

func (p *Prng) Underlyer(nonZero bool) Underlyer {
	out := Underlyer(0)
	for {
		out = Underlyer(p.Uint64() % p.MaxUnderlyer)
		if nonZero && out == 0 {
			continue
		}
		break
	}
	return out
}

func (p *Prng) UnderlyerSlice(size int, distinct, notAllZero, notAnyZero bool) []Underlyer {
	minSize := Underlyer(0)
	maxSize := p.MaxUnderlyer
	if size > 0 {
		minSize = Underlyer(size)
		maxSize = Underlyer(size) % p.MaxUnderlyer
	}
	out, err := randutils.RandomSliceOfIntegers[[]Underlyer](p, int(minSize), int(maxSize), 0, MaxUnderlyerValue, distinct, notAllZero, notAnyZero)
	if err != nil {
		panic(errs.WrapRandomSample(err, "could not sample a random slice of underlyers"))
	}
	return out
}

func (p *Prng) Int(nonZero bool) int {
	out := 0
	for {
		out = p.Rand().IntN(int(p.MaxUnderlyer))
		if nonZero && out == 0 {
			continue
		}
		break
	}
	return out
}

func (p *Prng) Clone() Prng {
	lo := p.lo
	hi := p.hi
	src := rand.NewPCG(lo, hi)
	return Prng{
		PCG: PCG{
			lo:  lo,
			hi:  hi,
			src: src,
			r:   rand.New(src),
		},
		MaxUnderlyer: p.MaxUnderlyer,
	}
}

func NewPrng() *Prng {
	lo := uint64(0)
	hi := uint64(0)
	src := rand.NewPCG(lo, hi)
	return &Prng{
		PCG: PCG{
			lo:  lo,
			hi:  hi,
			src: src,
			r:   rand.New(src),
		},
		MaxUnderlyer: MaxUnderlyerValue,
	}
}
