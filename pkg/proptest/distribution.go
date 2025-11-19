package proptest

import (
	"math/rand/v2"

	"golang.org/x/exp/constraints"
)

type Distribution[V any] interface {
	Draw() V
}

func DiracDistribution[V any](value V) Distribution[V] {
	return &dirac[V]{value}
}

type dirac[V any] struct {
	value V
}

func (c *dirac[V]) Draw() V {
	return c.value
}

func UniformDistribution[I constraints.Integer](lo, hi I) Distribution[I] {
	return &uniform[I]{lo, hi}
}

type uniform[I constraints.Integer] struct {
	lo, hi I
}

func (s *uniform[I]) Draw() I {
	if s.hi <= s.lo {
		panic("RandomInt: hi must be > lo")
	}

	width := s.hi - s.lo
	if width <= 0 {
		panic("RandomInt: range too large for underlying type")
	}

	offset := rand.N(width)
	return s.lo + offset
}

func FiniteSupportDistribution[V any](elements []V) Distribution[V] {
	return &finiteSupport[V]{elements}
}

type finiteSupport[V any] struct {
	elements []V
}

func (a *finiteSupport[V]) Draw() V {
	idx := rand.N(len(a.elements))
	return a.elements[idx]
}

// *** Combinators ***

func Repeated[V any](dist Distribution[V], length int) Distribution[[]V] {
	return &repeated[V]{
		dist,
		length,
	}
}

type repeated[V any] struct {
	dist   Distribution[V]
	length int
}

func (i *repeated[V]) Draw() []V {
	result := make([]V, i.length)
	for j := range i.length {
		result[j] = i.dist.Draw()
	}
	return result
}

func OneOf[V any](ds ...Distribution[V]) Distribution[V] {
	if len(ds) == 0 {
		panic("OneOf: empty")
	}
	return &oneOf[V]{ds: ds}
}

type oneOf[V any] struct {
	ds []Distribution[V]
}

func (o *oneOf[V]) Draw() V {
	idx := rand.N(len(o.ds))
	return o.ds[idx].Draw()
}

func Map[A, B any](d Distribution[A], f func(A) B) Distribution[B] {
	return &mapped[A, B]{d, f}
}

type mapped[A, B any] struct {
	d Distribution[A]
	f func(A) B
}

func (m *mapped[A, B]) Draw() B {
	return m.f(m.d.Draw())
}

func Bind[A, B any](d Distribution[A], f func(A) Distribution[B]) Distribution[B] {
	return &bound[A, B]{d, f}
}

type bound[A, B any] struct {
	d Distribution[A]
	f func(A) Distribution[B]
}

func (b *bound[A, B]) Draw() B {
	return b.f(b.d.Draw()).Draw()
}

func Filter[V any](d Distribution[V], pred func(V) bool, maxAttempts int) Distribution[V] {
	return &filtered[V]{d, pred, maxAttempts}
}

type filtered[V any] struct {
	d           Distribution[V]
	pred        func(V) bool
	maxAttempts int
}

func (f *filtered[V]) Draw() V {
	for range f.maxAttempts {
		v := f.d.Draw()
		if f.pred(v) {
			return v
		}
	}
	panic("Filter: predicate too selective")
}

func BernoulliDistribution(p float64) Distribution[bool] {
	if p <= 0 {
		return DiracDistribution(false)
	}
	if p >= 1 {
		return DiracDistribution(true)
	}
	return bernoulli(p)
}

type bernoulli float64

func (b bernoulli) Draw() bool {
	return rand.Float64() < float64(b)
}

func OptionalDistribution[V any](d Distribution[V], pSome float64) Distribution[*V] {
	return Bind(BernoulliDistribution(pSome), func(b bool) Distribution[*V] {
		if !b {
			return DiracDistribution[*V](nil)
		}
		return Map(d, func(v V) *V { return &v })
	})
}
