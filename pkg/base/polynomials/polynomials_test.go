package polynomials

import (
	crand "crypto/rand"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
)

var supportedScalarFields = []curves.ScalarField{
	k256.NewCurve().ScalarField(),
	p256.NewCurve().ScalarField(),
	edwards25519.NewCurve().ScalarField(),
	pallas.NewCurve().ScalarField(),
	bls12381.NewG1().ScalarField(),
	bls12381.NewG2().ScalarField(),
}

const repetitions = 256
const maxDegree = 32

func Test_ImplementsPolynomial(t *testing.T) {
	t.Parallel()

	for _, field := range supportedScalarFields {
		field := field
		set := GetScalarUnivariatePolynomialsSet(field)
		var _ AbstractUnivariatePolynomialsSet[curves.ScalarField, curves.Scalar] = set
		var _ AbstractUnivariatePolynomial[curves.ScalarField, curves.Scalar] = set.Element()
	}
}

func Test_ImplementsRing(t *testing.T) {
	t.Parallel()

	for _, field := range supportedScalarFields {
		field := field
		set := GetScalarUnivariatePolynomialsSet(field)
		var _ algebra.AbstractRing[*UnivariatePolynomialsSet[curves.ScalarField, curves.Scalar], *UnivariatePolynomial[curves.ScalarField, curves.Scalar]] = set
		var _ algebra.AbstractRingElement[*UnivariatePolynomialsSet[curves.ScalarField, curves.Scalar], *UnivariatePolynomial[curves.ScalarField, curves.Scalar]] = set.Element()
	}
}

func Test_ImplementsVectorSpace(t *testing.T) {
	t.Parallel()

	for _, field := range supportedScalarFields {
		field := field
		set := GetScalarUnivariatePolynomialsSet(field)
		var _ algebra.AbstractAlgebra[*UnivariatePolynomialsSet[curves.ScalarField, curves.Scalar], *UnivariatePolynomial[curves.ScalarField, curves.Scalar], curves.Scalar, curves.ScalarField] = set
		var _ algebra.AbstractAlgebraElement[*UnivariatePolynomialsSet[curves.ScalarField, curves.Scalar], *UnivariatePolynomial[curves.ScalarField, curves.Scalar], curves.Scalar] = set.Element()
	}
}

func Test_Add(t *testing.T) {
	t.Parallel()

	for _, field := range supportedScalarFields {
		field := field
		set := GetScalarUnivariatePolynomialsSet(field)

		t.Run(field.Name(), func(t *testing.T) {
			t.Parallel()

			for i := 0; i < repetitions; i++ {
				aDegree := rand.Intn(maxDegree)
				a, err := set.NewUnivariatePolynomialRandom(aDegree, crand.Reader)
				require.NoError(t, err)

				bDegree := rand.Intn(maxDegree)
				b, err := set.NewUnivariatePolynomialRandom(bDegree, crand.Reader)
				require.NoError(t, err)

				c := a.Add(b)
				require.True(t, b.Equal(c.Sub(a)))
				require.True(t, a.Equal(c.Sub(b)))

				y, err := field.Random(crand.Reader)
				require.NoError(t, err)

				ya := a.Eval(y)
				yb := b.Eval(y)
				yc := c.Eval(y)
				require.True(t, yc.Equal(ya.Add(yb)))
			}
		})
	}
}

func Test_Sub(t *testing.T) {
	t.Parallel()

	for _, field := range supportedScalarFields {
		field := field
		set := GetScalarUnivariatePolynomialsSet(field)

		t.Run(field.Name(), func(t *testing.T) {
			t.Parallel()

			for i := 0; i < repetitions; i++ {
				aDegree := rand.Intn(maxDegree)
				a, err := set.NewUnivariatePolynomialRandom(aDegree, crand.Reader)
				require.NoError(t, err)

				bDegree := rand.Intn(maxDegree)
				b, err := set.NewUnivariatePolynomialRandom(bDegree, crand.Reader)
				require.NoError(t, err)

				c := a.Sub(b)
				require.True(t, a.Equal(c.Add(b)))
				require.True(t, b.Equal(a.Sub(c)))

				y, err := field.Random(crand.Reader)
				require.NoError(t, err)

				ya := a.Eval(y)
				yb := b.Eval(y)
				yc := c.Eval(y)
				require.True(t, yc.Equal(ya.Sub(yb)))
			}
		})
	}
}

func Test_Mul(t *testing.T) {
	t.Parallel()

	for _, field := range supportedScalarFields {
		field := field
		set := GetScalarUnivariatePolynomialsSet(field)

		t.Run(field.Name(), func(t *testing.T) {
			t.Parallel()

			for i := 0; i < repetitions; i++ {
				aDegree := rand.Intn(maxDegree)
				a, err := set.NewUnivariatePolynomialRandom(aDegree, crand.Reader)
				require.NoError(t, err)

				bDegree := rand.Intn(maxDegree)
				b, err := set.NewUnivariatePolynomialRandom(bDegree, crand.Reader)
				require.NoError(t, err)

				c := a.Mul(b)
				aq, ar := c.EuclideanDiv(b)
				require.True(t, aq.Equal(a))
				require.True(t, ar.IsAdditiveIdentity())

				y, err := field.Random(crand.Reader)
				require.NoError(t, err)

				ya := a.Eval(y)
				yb := b.Eval(y)
				yc := c.Eval(y)
				require.True(t, yc.Equal(ya.Mul(yb)))
			}
		})
	}
}

func Test_Div(t *testing.T) {
	t.Parallel()

	for _, field := range supportedScalarFields {
		field := field
		set := GetScalarUnivariatePolynomialsSet(field)

		t.Run(field.Name(), func(t *testing.T) {
			t.Parallel()

			for i := 0; i < repetitions; i++ {
				aDegree := rand.Intn(maxDegree)
				a, err := set.NewUnivariatePolynomialRandom(aDegree, crand.Reader)
				require.NoError(t, err)

				bDegree := rand.Intn(maxDegree)
				b, err := set.NewUnivariatePolynomialRandom(bDegree, crand.Reader)
				require.NoError(t, err)

				q, r := a.EuclideanDiv(b)
				require.True(t, q.Degree() <= a.Degree())
				require.True(t, r.Degree() < b.Degree())

				aCheck := b.Mul(q).Add(r)
				require.True(t, a.Equal(aCheck))
			}
		})
	}
}

func Test_Gcd(t *testing.T) {
	t.Parallel()

	for _, field := range supportedScalarFields {
		field := field
		set := GetScalarUnivariatePolynomialsSet(field)

		t.Run(field.Name(), func(t *testing.T) {
			t.Parallel()

			for i := 0; i < repetitions; i++ {
				aDegree := rand.Intn(maxDegree)
				a, err := set.NewUnivariatePolynomialRandom(aDegree, crand.Reader)
				require.NoError(t, err)

				bDegree := rand.Intn(maxDegree)
				b, err := set.NewUnivariatePolynomialRandom(bDegree, crand.Reader)
				require.NoError(t, err)

				c := a.EuclideanGcd(b)

				aq, ar := a.EuclideanDiv(c)
				require.True(t, ar.IsAdditiveIdentity())

				bq, br := b.EuclideanDiv(c)
				require.True(t, br.IsAdditiveIdentity())

				check := c.Mul(aq.Add(bq))
				require.True(t, check.Equal(a.Add(b)))

				y, err := field.Random(crand.Reader)
				require.NoError(t, err)

				ay := a.Eval(y).Add(b.Eval(y))
				ayCheck := aq.Eval(y).Add(bq.Eval(y)).Mul(c.Eval(y))
				require.True(t, ay.Equal(ayCheck))
			}
		})
	}
}

func Test_Lcm(t *testing.T) {
	t.Parallel()

	for _, field := range supportedScalarFields {
		field := field
		set := GetScalarUnivariatePolynomialsSet(field)

		t.Run(field.Name(), func(t *testing.T) {
			t.Parallel()

			for i := 0; i < repetitions; i++ {
				aDegree := rand.Intn(maxDegree)
				a, err := set.NewUnivariatePolynomialRandom(aDegree, crand.Reader)
				require.NoError(t, err)

				bDegree := rand.Intn(maxDegree)
				b, err := set.NewUnivariatePolynomialRandom(bDegree, crand.Reader)
				require.NoError(t, err)

				c := a.EuclideanLcm(b)

				_, ar := c.EuclideanDiv(a)
				require.True(t, ar.IsAdditiveIdentity())

				_, br := c.EuclideanDiv(b)
				require.True(t, br.IsAdditiveIdentity())
			}
		})
	}
}
