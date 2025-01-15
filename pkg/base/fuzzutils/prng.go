package fuzzutils

import (
	"io"
	"math/rand/v2"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils/randutils"
)

var _ io.Reader = (*PCG)(nil)
var _ rand.Source = (*PCG)(nil)

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

func (p *Prng) Bool() bool {
	return p.Rand().IntN(2) == 1
}

func (p *Prng) Underlyer(nonZero bool) Underlyer {
	var out Underlyer
	for {
		out = Underlyer(p.Uint64() % p.MaxUnderlyer) //nolint:unconvert // intentional, for readability.
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
	var out int
	for {
		out = p.Rand().IntN(int(p.MaxUnderlyer) + 1)
		if nonZero && out == 0 {
			continue
		}
		break
	}
	return out
}

func (p *Prng) IntRange(a, b int) int {
	if b < a {
		return 0
	}
	return p.Rand().IntN(b-a+1) + a
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
