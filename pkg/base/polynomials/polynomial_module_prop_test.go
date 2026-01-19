package polynomials_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

type MVP = *polynomials.ModuleValuedPolynomial[*k256.Point, *k256.Scalar]

func ModuleValuedPolynomialGenerator(t *testing.T) *rapid.Generator[MVP] {
	t.Helper()
	curve := k256.NewCurve()
	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	return rapid.Custom(func(rt *rapid.T) MVP {
		degree := rapid.IntRange(0, 10).Draw(rt, "degree")
		poly, err := polyModule.RandomModuleValuedPolynomial(degree, pcg.NewRandomised())
		if err != nil {
			panic(err)
		}
		return poly
	})
}

func TestPolynomialModuleProperties(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	scalarField := k256.NewScalarField()
	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	mvpOp := &properties.BinaryOperator[MVP]{
		Name: "Op",
		Func: func(a, b MVP) MVP { return a.Op(b) },
	}
	mvpIdentity := &properties.Constant[MVP]{
		Name:  "OpIdentity",
		Value: polyModule.OpIdentity,
	}
	mvpInv := &properties.UnaryOperator[MVP]{
		Name: "OpInv",
		Func: func(a MVP) MVP { return a.OpInv() },
	}
	mvpScalarOp := &properties.Action[*k256.Scalar, MVP]{
		Name: "ScalarOp",
		Func: func(s *k256.Scalar, a MVP) MVP { return a.ScalarOp(s) },
	}

	var suite = properties.PolynomialModule[
		*polynomials.PolynomialModule[*k256.Point, *k256.Scalar],
		*k256.Curve,
	](
		t, polyModule, scalarField,
		ModuleValuedPolynomialGenerator(t), ScalarGenerator(t),
		mvpOp, mvpIdentity, mvpInv, mvpScalarOp,
	)
	suite.Check(t)
}
