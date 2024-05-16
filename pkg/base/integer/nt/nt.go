package nt

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type Symbol[S integer.Z[S, E], E integer.Int[S, E]] interface {
	IsOne() bool
	ISZero() bool
	IsNegativeOne() bool
	Value() E
}

func GCD[S integer.Z[S, E], E integer.Int[S, E]](x E, ys ...E) (E, error) {
	panic("implement me")
}

func VarTimeGCD[S integer.Z[S, E], E integer.Int[S, E]](x E, ys ...E) (E, error) {
	panic("implement me")
}

func LCM[S integer.Z[S, E], E integer.Int[S, E]](x E, ys ...E) (E, error) {
	panic("implement me")
}

func VarTimeLCM[S integer.Z[S, E], E integer.Int[S, E]](x E, ys ...E) (E, error) {
	panic("implement me")
}

func CoPrime[S integer.Z[S, E], E integer.Int[S, E]](x E, ys ...E) (E, error) {
	panic("implement me")
}

func IsPrime[S integer.N[S, E], E integer.Nat[S, E]](x E) bool {
	panic("implement me")
}

func IsProbablyPrime[S integer.N[S, E], E integer.Nat[S, E]]() bool {
	panic("implement me")
}

func GeneratePrimes[S integer.N[S, E], E integer.Nat[S, E]](prng io.Reader, bits, count uint) (E, error) {
	panic("implement me")
}

func GenerateSafePrimes[S integer.N[S, E], E integer.Nat[S, E]](prng io.Reader, bits, count uint) (E, error) {
	panic("implement me")
}

func Jacobi[Z integer.Z[Z, I], I integer.Int[Z, I], NP integer.PositiveNaturalRg[NP, N], N integer.PositiveNaturalRgElement[NP, N]](a I, p N) (Symbol[Z, I], error) {
	panic("implement me")
}

func Legendre[Z integer.Z[Z, I], I integer.Int[Z, I], NP integer.PositiveNaturalRg[NP, N], N integer.PositiveNaturalRgElement[NP, N]](a I, p N) (Symbol[Z, I], error) {
	panic("implement me")
}
