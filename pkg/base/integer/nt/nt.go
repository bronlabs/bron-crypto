package nt

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/itertools"
)

type Symbol[S integer.Z[S, E], E integer.Int[S, E]] interface {
	IsOne() bool
	ISZero() bool
	IsNegativeOne() bool
	Value() E
}

func GCD[S integer.Z[S, E], E integer.Int[S, E]](x E, ys ...E) E {
	panic("implement me")
}

func LCM[S integer.Z[S, E], E integer.Int[S, E]](gcd func(x E, y E) E, x E, ys ...E) E {
	f := func(x, y E) E {
		q, r, err := x.Mul(y).EuclideanDiv(gcd(x, y))
		if !r.IsZero() {
			panic("non zero remainder")
		}
		return q
	}
	if len(ys) == 0 {
		return x
	}
	return itertools.Fold(f, f(x, ys[0]), ys[1:]...)
}

func CoPrime[S integer.Z[S, E], E integer.Int[S, E]](x E, ys ...E) (E, error) {
	panic("implement me")
}

func IsPrime[S integer.NaturalPreSemiRing[S, E], E integer.NaturalPreSemiRingElement[S, E]](x E) bool {
	panic("implement me")
}

func IsProbablyPrime[S integer.NaturalPreSemiRing[S, E], E integer.NaturalPreSemiRingElement[S, E]]() bool {
	panic("implement me")
}

func GeneratePrimes[S integer.NPlus[S, E], E integer.NatPlus[S, E]](prng io.Reader, bits, count uint) (E, error) {
	panic("implement me")
}

func GenerateSafePrimes[S integer.NPlus[S, E], E integer.NatPlus[S, E]](prng io.Reader, bits, count uint) (E, error) {
	panic("implement me")
}

func Jacobi[Z integer.Z[Z, I], I integer.Int[Z, I], NP integer.NaturalPreSemiRing[NP, N], N integer.NaturalPreSemiRingElement[NP, N]](a I, p N) (Symbol[Z, I], error) {
	panic("implement me")
}

func Legendre[Z integer.Z[Z, I], I integer.Int[Z, I], NP integer.NaturalPreSemiRing[NP, N], N integer.NaturalPreSemiRingElement[NP, N]](a I, p N) (Symbol[Z, I], error) {
	panic("implement me")
}
