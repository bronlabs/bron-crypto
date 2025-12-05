package algebrautils_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

// naiveMultiScalarMul computes multi-scalar multiplication using the naive method:
// sum(scalars[i] * points[i]) for all i
func naiveMultiScalarMul[E algebra.MonoidElement[E], S algebra.NatLike[S]](
	scalars []S,
	points []E,
) E {
	monoid := algebra.StructureMustBeAs[algebra.Monoid[E]](points[0].Structure())
	result := monoid.OpIdentity()
	for i := range points {
		result = result.Op(algebrautils.ScalarMul(points[i], scalars[i]))
	}
	return result
}

func BenchmarkMultiScalarMul_K256(b *testing.B) {
	curve := k256.NewCurve()
	scalarField := k256.NewScalarField()

	for _, n := range []int{10, 50, 100, 256, 512} {
		points := make([]*k256.Point, n)
		scalars := make([]*k256.Scalar, n)

		for i := range n {
			p, _ := curve.Random(crand.Reader)
			points[i] = p
			s, _ := scalarField.Random(crand.Reader)
			scalars[i] = s
		}

		b.Run(fmt.Sprintf("Pippenger/n=%d", n), func(b *testing.B) {
			for range b.N {
				_ = algebrautils.MultiScalarMul(scalars, points)
			}
		})

		b.Run(fmt.Sprintf("Naive/n=%d", n), func(b *testing.B) {
			for range b.N {
				_ = naiveMultiScalarMul(scalars, points)
			}
		})
	}
}

func BenchmarkMultiScalarMul_Edwards25519(b *testing.B) {
	curve := edwards25519.NewPrimeSubGroup()
	scalarField := edwards25519.NewScalarField()

	for _, n := range []int{10, 50, 100, 256, 512} {
		points := make([]*edwards25519.PrimeSubGroupPoint, n)
		scalars := make([]*edwards25519.Scalar, n)

		for i := range n {
			p, _ := curve.Random(crand.Reader)
			points[i] = p
			s, _ := scalarField.Random(crand.Reader)
			scalars[i] = s
		}

		b.Run(fmt.Sprintf("Pippenger/n=%d", n), func(b *testing.B) {
			for range b.N {
				_ = algebrautils.MultiScalarMul(scalars, points)
			}
		})

		b.Run(fmt.Sprintf("Naive/n=%d", n), func(b *testing.B) {
			for range b.N {
				_ = naiveMultiScalarMul(scalars, points)
			}
		})
	}
}
