package polynomials_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func TestNewPolynomialModule(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	t.Run("valid module", func(t *testing.T) {
		polyMod, err := polynomials.NewPolynomialModule(curve)
		require.NoError(t, err)
		require.NotNil(t, polyMod)
	})

	t.Run("nil module returns error", func(t *testing.T) {
		_, err := polynomials.NewPolynomialModule[*k256.Point, *k256.Scalar](nil)
		require.Error(t, err)
	})
}

func TestPolynomialModuleNew(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	g := curve.Generator()

	t.Run("empty coefficients returns identity", func(t *testing.T) {
		poly, err := polyMod.New()
		require.NoError(t, err)
		require.True(t, poly.IsOpIdentity())
	})

	t.Run("single coefficient", func(t *testing.T) {
		poly, err := polyMod.New(g.Clone())
		require.NoError(t, err)
		require.Equal(t, 0, poly.Degree())
		require.True(t, poly.ConstantTerm().Equal(g))
	})

	t.Run("multiple coefficients", func(t *testing.T) {
		g2 := g.Double()
		g3 := g.ScalarOp(k256.NewScalarField().FromUint64(3))
		poly, err := polyMod.New(g.Clone(), g2, g3)
		require.NoError(t, err)
		require.Equal(t, 2, poly.Degree())
		coeffs := poly.Coefficients()
		require.Len(t, coeffs, 3)
	})

	t.Run("nil coefficient returns error", func(t *testing.T) {
		_, err := polyMod.New(g.Clone(), nil, g.Clone())
		require.Error(t, err)
	})
}

func TestPolynomialModuleName(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	name := polyMod.Name()
	require.Contains(t, name, "PolynomialModule")
}

func TestPolynomialModuleOrder(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	order := polyMod.Order()
	require.False(t, order.IsFinite())
}

func TestPolynomialModuleElementSize(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	// Variable-length element, returns -1
	require.Equal(t, -1, polyMod.ElementSize())
}

func TestPolynomialModuleOpIdentity(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	identity := polyMod.OpIdentity()
	require.True(t, identity.IsOpIdentity())
	require.Equal(t, -1, identity.Degree())
}

func TestPolynomialModuleScalarStructure(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	scalarStruct := polyMod.ScalarStructure()
	require.NotNil(t, scalarStruct)
}

func TestPolynomialModuleFromBytes(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	g := curve.Generator()

	t.Run("roundtrip", func(t *testing.T) {
		original, err := polyMod.New(g.Clone(), g.Double())
		require.NoError(t, err)

		bytes := original.Bytes()
		recovered, err := polyMod.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, original.Equal(recovered))
	})

	t.Run("empty bytes returns identity", func(t *testing.T) {
		poly, err := polyMod.FromBytes([]byte{})
		require.NoError(t, err)
		require.True(t, poly.IsOpIdentity())
	})

	t.Run("invalid length returns error", func(t *testing.T) {
		_, err := polyMod.FromBytes([]byte{1, 2, 3})
		require.Error(t, err)
	})
}

func TestPolynomialModuleRandomModuleValuedPolynomial(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	prng := pcg.NewRandomised()

	t.Run("degree 0", func(t *testing.T) {
		poly, err := polyMod.RandomModuleValuedPolynomial(0, prng)
		require.NoError(t, err)
		require.Equal(t, 0, poly.Degree())
	})

	t.Run("degree 3", func(t *testing.T) {
		poly, err := polyMod.RandomModuleValuedPolynomial(3, prng)
		require.NoError(t, err)
		require.Equal(t, 3, poly.Degree())
	})

	t.Run("negative degree returns error", func(t *testing.T) {
		_, err := polyMod.RandomModuleValuedPolynomial(-1, prng)
		require.Error(t, err)
	})
}

func TestPolynomialModuleRandomWithConstantTerm(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	prng := pcg.NewRandomised()
	g := curve.Generator()

	t.Run("preserves constant term", func(t *testing.T) {
		poly, err := polyMod.RandomModuleValuedPolynomialWithConstantTerm(2, g.Clone(), prng)
		require.NoError(t, err)
		require.True(t, poly.ConstantTerm().Equal(g))
	})

	t.Run("negative degree returns error", func(t *testing.T) {
		_, err := polyMod.RandomModuleValuedPolynomialWithConstantTerm(-1, g.Clone(), prng)
		require.Error(t, err)
	})
}

func TestPolynomialModuleMultiScalarOp(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	t.Run("multi scalar op", func(t *testing.T) {
		p1, err := polyMod.New(g.Clone())
		require.NoError(t, err)
		p2, err := polyMod.New(g.Double())
		require.NoError(t, err)

		scalars := []*k256.Scalar{field.FromUint64(2), field.FromUint64(3)}
		polys := []*polynomials.ModuleValuedPolynomial[*k256.Point, *k256.Scalar]{p1, p2}

		result, err := polyMod.MultiScalarOp(scalars, polys)
		require.NoError(t, err)
		require.NotNil(t, result)

		// 2*G + 3*(2G) = 2G + 6G = 8G
		expected := g.ScalarOp(field.FromUint64(8))
		require.True(t, result.ConstantTerm().Equal(expected))
	})

	t.Run("length mismatch returns error", func(t *testing.T) {
		p1, _ := polyMod.New(g.Clone())
		scalars := []*k256.Scalar{field.FromUint64(1), field.FromUint64(2)}
		polys := []*polynomials.ModuleValuedPolynomial[*k256.Point, *k256.Scalar]{p1}

		_, err := polyMod.MultiScalarOp(scalars, polys)
		require.Error(t, err)
	})

	t.Run("empty input returns error", func(t *testing.T) {
		scalars := []*k256.Scalar{}
		polys := []*polynomials.ModuleValuedPolynomial[*k256.Point, *k256.Scalar]{}

		_, err := polyMod.MultiScalarOp(scalars, polys)
		require.Error(t, err)
	})
}

func TestModuleValuedPolynomialOp(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	t.Run("addition of same degree", func(t *testing.T) {
		p1, _ := polyMod.New(g.Clone(), g.Double())
		p2, _ := polyMod.New(g.Double(), g.Clone())
		sum := p1.Op(p2)

		// (G, 2G) + (2G, G) = (3G, 3G)
		expected := g.ScalarOp(k256.NewScalarField().FromUint64(3))
		require.True(t, sum.ConstantTerm().Equal(expected))
		coeffs := sum.Coefficients()
		require.True(t, coeffs[1].Equal(expected))
	})

	t.Run("addition of different degrees", func(t *testing.T) {
		p1, _ := polyMod.New(g.Clone())
		p2, _ := polyMod.New(g.Clone(), g.Double(), g.Clone())
		sum := p1.Op(p2)

		require.Equal(t, 2, sum.Degree())
	})

	t.Run("add identity", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double())
		sum := p.Op(polyMod.OpIdentity())
		require.True(t, sum.Equal(p))
	})
}

func TestModuleValuedPolynomialOpInv(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	t.Run("op with inverse is identity", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double())
		inv := p.OpInv()
		result := p.Op(inv)
		require.True(t, result.IsOpIdentity())
	})

	t.Run("TryOpInv succeeds", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone())
		inv, err := p.TryOpInv()
		require.NoError(t, err)
		require.True(t, inv.Equal(p.OpInv()))
	})
}

func TestModuleValuedPolynomialOpElement(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	p, _ := polyMod.New(g.Clone(), g.Double())
	result := p.OpElement(g.Clone())

	// Adds G to constant term: (G, 2G) + G = (2G, 2G)
	expected := g.Double()
	require.True(t, result.ConstantTerm().Equal(expected))
	// Other coefficients unchanged
	require.True(t, result.Coefficients()[1].Equal(g.Double()))
}

func TestModuleValuedPolynomialScalarOp(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	t.Run("scalar multiplication", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double())
		scalar := field.FromUint64(3)
		result := p.ScalarOp(scalar)

		// 3 * (G, 2G) = (3G, 6G)
		expectedConst := g.ScalarOp(field.FromUint64(3))
		expectedLinear := g.ScalarOp(field.FromUint64(6))
		require.True(t, result.ConstantTerm().Equal(expectedConst))
		require.True(t, result.Coefficients()[1].Equal(expectedLinear))
	})

	t.Run("multiply by zero", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone())
		result := p.ScalarOp(field.Zero())
		require.True(t, result.IsOpIdentity())
	})

	t.Run("multiply by one", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double())
		result := p.ScalarOp(field.One())
		require.True(t, result.Equal(p))
	})
}

func TestModuleValuedPolynomialDegree(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()
	identity := curve.OpIdentity()

	t.Run("identity polynomial has degree -1", func(t *testing.T) {
		require.Equal(t, -1, polyMod.OpIdentity().Degree())
	})

	t.Run("non-zero constant has degree 0", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone())
		require.Equal(t, 0, p.Degree())
	})

	t.Run("linear has degree 1", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double())
		require.Equal(t, 1, p.Degree())
	})

	t.Run("trailing identities ignored", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double(), identity.Clone())
		require.Equal(t, 1, p.Degree())
	})
}

func TestModuleValuedPolynomialConstantTerm(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	p, _ := polyMod.New(g.Clone(), g.Double(), g.Clone())
	require.True(t, p.ConstantTerm().Equal(g))
}

func TestModuleValuedPolynomialLeadingCoefficient(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()
	identity := curve.OpIdentity()

	t.Run("non-zero polynomial", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double())
		require.True(t, p.LeadingCoefficient().Equal(g.Double()))
	})

	t.Run("identity polynomial returns identity", func(t *testing.T) {
		require.True(t, polyMod.OpIdentity().LeadingCoefficient().IsOpIdentity())
	})

	t.Run("trailing identities handled", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double(), identity.Clone())
		require.True(t, p.LeadingCoefficient().Equal(g.Double()))
	})
}

func TestModuleValuedPolynomialIsConstant(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	t.Run("constant is constant", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone())
		require.True(t, p.IsConstant())
	})

	t.Run("identity is constant (degree <= 0)", func(t *testing.T) {
		// ModuleValuedPolynomial.IsConstant uses Degree() <= 0
		require.True(t, polyMod.OpIdentity().IsConstant())
	})

	t.Run("linear is not constant", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double())
		require.False(t, p.IsConstant())
	})
}

func TestModuleValuedPolynomialEval(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	t.Run("eval at zero gives constant term", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double())
		result := p.Eval(field.Zero())
		require.True(t, result.Equal(g))
	})

	t.Run("eval at one sums coefficients", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double()) // G + 2Gx
		result := p.Eval(field.One())              // G + 2G = 3G
		expected := g.ScalarOp(field.FromUint64(3))
		require.True(t, result.Equal(expected))
	})

	t.Run("eval linear polynomial", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double()) // G + 2Gx
		result := p.Eval(field.FromUint64(3))      // G + 2G*3 = G + 6G = 7G
		expected := g.ScalarOp(field.FromUint64(7))
		require.True(t, result.Equal(expected))
	})
}

func TestModuleValuedPolynomialDerivative(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	t.Run("constant derivative is identity", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone())
		deriv := p.Derivative()
		require.True(t, deriv.IsOpIdentity())
	})

	t.Run("linear derivative is constant", func(t *testing.T) {
		p, _ := polyMod.New(g.Clone(), g.Double()) // G + 2Gx
		deriv := p.Derivative()                    // 2G
		require.Equal(t, 0, deriv.Degree())
		require.True(t, deriv.ConstantTerm().Equal(g.Double()))
	})

	t.Run("quadratic derivative", func(t *testing.T) {
		threeG := g.ScalarOp(field.FromUint64(3))
		p, _ := polyMod.New(g.Clone(), g.Double(), threeG) // G + 2Gx + 3Gx^2
		deriv := p.Derivative()                            // 2G + 6Gx
		require.Equal(t, 1, deriv.Degree())
		require.True(t, deriv.ConstantTerm().Equal(g.Double()))
		expected := g.ScalarOp(field.FromUint64(6))
		require.True(t, deriv.Coefficients()[1].Equal(expected))
	})
}

func TestModuleValuedPolynomialPolynomialOp(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)
	g := curve.Generator()

	t.Run("constant MVP times constant polynomial", func(t *testing.T) {
		// 3G * 5 = 15G
		threeG := g.ScalarOp(field.FromUint64(3))
		mvp, _ := polyMod.New(threeG)
		sp, _ := polyRing.New(field.FromUint64(5))

		result := mvp.PolynomialOp(sp)
		require.Equal(t, 0, result.Degree())

		expected := g.ScalarOp(field.FromUint64(15))
		require.True(t, result.ConstantTerm().Equal(expected))
	})

	t.Run("constant MVP times linear polynomial", func(t *testing.T) {
		// 2G * (3 + 4x) = 6G + 8Gx
		twoG := g.Double()
		mvp, _ := polyMod.New(twoG)
		sp, _ := polyRing.New(field.FromUint64(3), field.FromUint64(4))

		result := mvp.PolynomialOp(sp)
		require.Equal(t, 1, result.Degree())

		sixG := g.ScalarOp(field.FromUint64(6))
		eightG := g.ScalarOp(field.FromUint64(8))
		require.True(t, result.ConstantTerm().Equal(sixG))
		require.True(t, result.Coefficients()[1].Equal(eightG))
	})

	t.Run("linear MVP times constant polynomial", func(t *testing.T) {
		// (G + 2Gx) * 3 = 3G + 6Gx
		mvp, _ := polyMod.New(g.Clone(), g.Double())
		sp, _ := polyRing.New(field.FromUint64(3))

		result := mvp.PolynomialOp(sp)
		require.Equal(t, 1, result.Degree())

		threeG := g.ScalarOp(field.FromUint64(3))
		sixG := g.ScalarOp(field.FromUint64(6))
		require.True(t, result.ConstantTerm().Equal(threeG))
		require.True(t, result.Coefficients()[1].Equal(sixG))
	})

	t.Run("linear MVP times linear polynomial", func(t *testing.T) {
		// (G + 2Gx) * (2 + x) = 2G + Gx + 4Gx + 2Gx^2 = 2G + 5Gx + 2Gx^2
		mvp, _ := polyMod.New(g.Clone(), g.Double())
		sp, _ := polyRing.New(field.FromUint64(2), field.One())

		result := mvp.PolynomialOp(sp)
		require.Equal(t, 2, result.Degree())

		twoG := g.Double()
		fiveG := g.ScalarOp(field.FromUint64(5))
		require.True(t, result.ConstantTerm().Equal(twoG))
		require.True(t, result.Coefficients()[1].Equal(fiveG))
		require.True(t, result.Coefficients()[2].Equal(twoG))
	})

	t.Run("quadratic MVP times linear polynomial", func(t *testing.T) {
		// (G + 2Gx + 3Gx^2) * (1 + x) = G + Gx + 2Gx + 2Gx^2 + 3Gx^2 + 3Gx^3
		//                             = G + 3Gx + 5Gx^2 + 3Gx^3
		threeG := g.ScalarOp(field.FromUint64(3))
		mvp, _ := polyMod.New(g.Clone(), g.Double(), threeG)
		sp, _ := polyRing.New(field.One(), field.One())

		result := mvp.PolynomialOp(sp)
		require.Equal(t, 3, result.Degree())

		fiveG := g.ScalarOp(field.FromUint64(5))
		require.True(t, result.ConstantTerm().Equal(g))
		require.True(t, result.Coefficients()[1].Equal(threeG))
		require.True(t, result.Coefficients()[2].Equal(fiveG))
		require.True(t, result.Coefficients()[3].Equal(threeG))
	})

	t.Run("multiply by zero polynomial", func(t *testing.T) {
		mvp, _ := polyMod.New(g.Clone(), g.Double())
		result := mvp.PolynomialOp(polyRing.Zero())
		require.True(t, result.IsOpIdentity())
	})

	t.Run("multiply by one polynomial", func(t *testing.T) {
		mvp, _ := polyMod.New(g.Clone(), g.Double())
		result := mvp.PolynomialOp(polyRing.One())
		require.True(t, result.Equal(mvp))
	})

	t.Run("multiply by x (shifts coefficients)", func(t *testing.T) {
		// (G + 2Gx) * x = Gx + 2Gx^2
		mvp, _ := polyMod.New(g.Clone(), g.Double())
		x, _ := polyRing.New(field.Zero(), field.One()) // 0 + 1*x

		result := mvp.PolynomialOp(x)
		require.Equal(t, 2, result.Degree())

		require.True(t, result.ConstantTerm().IsOpIdentity())
		require.True(t, result.Coefficients()[1].Equal(g))
		require.True(t, result.Coefficients()[2].Equal(g.Double()))
	})

	t.Run("degree of product equals sum of degrees", func(t *testing.T) {
		// deg(p * q) = deg(p) + deg(q) when leading coefficients are non-zero
		mvp, _ := polyMod.New(g.Clone(), g.Double(), g.Clone())      // degree 2
		sp, _ := polyRing.New(field.One(), field.One(), field.One()) // degree 2

		result := mvp.PolynomialOp(sp)
		require.Equal(t, 4, result.Degree()) // 2 + 2 = 4
	})

	t.Run("associativity with scalar multiplication", func(t *testing.T) {
		// (s * mvp) * poly == mvp * (s * poly)
		mvp, _ := polyMod.New(g.Clone(), g.Double())
		sp, _ := polyRing.New(field.FromUint64(2), field.One())
		s := field.FromUint64(5)

		// (5 * (G + 2Gx)) * (2 + x) = (5G + 10Gx) * (2 + x)
		left := mvp.ScalarOp(s).PolynomialOp(sp)

		// (G + 2Gx) * (5 * (2 + x)) = (G + 2Gx) * (10 + 5x)
		right := mvp.PolynomialOp(sp.ScalarMul(s))

		require.True(t, left.Equal(right))
	})

	t.Run("distributivity over MVP addition", func(t *testing.T) {
		// (mvp1 + mvp2) * poly == mvp1 * poly + mvp2 * poly
		mvp1, _ := polyMod.New(g.Clone(), g.Double())
		mvp2, _ := polyMod.New(g.Double(), g.Clone())
		sp, _ := polyRing.New(field.FromUint64(2), field.One())

		left := mvp1.Op(mvp2).PolynomialOp(sp)
		right := mvp1.PolynomialOp(sp).Op(mvp2.PolynomialOp(sp))

		require.True(t, left.Equal(right))
	})

	t.Run("distributivity over polynomial addition", func(t *testing.T) {
		// mvp * (poly1 + poly2) == mvp * poly1 + mvp * poly2
		mvp, _ := polyMod.New(g.Clone(), g.Double())
		sp1, _ := polyRing.New(field.FromUint64(2), field.One())
		sp2, _ := polyRing.New(field.One(), field.FromUint64(3))

		left := mvp.PolynomialOp(sp1.Add(sp2))
		right := mvp.PolynomialOp(sp1).Op(mvp.PolynomialOp(sp2))

		require.True(t, left.Equal(right))
	})
}

func TestModuleValuedPolynomialClone(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	original, _ := polyMod.New(g.Clone(), g.Double())
	clone := original.Clone()

	require.True(t, original.Equal(clone))

	// Verify deep copy
	coeffs := clone.Coefficients()
	require.True(t, coeffs[0].Equal(g))
}

func TestModuleValuedPolynomialEqual(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()
	identity := curve.OpIdentity()

	t.Run("equal polynomials", func(t *testing.T) {
		p1, _ := polyMod.New(g.Clone(), g.Double())
		p2, _ := polyMod.New(g.Clone(), g.Double())
		require.True(t, p1.Equal(p2))
	})

	t.Run("unequal polynomials", func(t *testing.T) {
		p1, _ := polyMod.New(g.Clone(), g.Double())
		p2, _ := polyMod.New(g.Double(), g.Clone())
		require.False(t, p1.Equal(p2))
	})

	t.Run("different degrees with trailing identities", func(t *testing.T) {
		p1, _ := polyMod.New(g.Clone(), g.Double())
		p2, _ := polyMod.New(g.Clone(), g.Double(), identity.Clone())
		require.True(t, p1.Equal(p2))
	})
}

func TestModuleValuedPolynomialHashCode(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	p1, _ := polyMod.New(g.Clone(), g.Double())
	p2, _ := polyMod.New(g.Clone(), g.Double())

	// Equal polynomials should have equal hash codes
	require.Equal(t, p1.HashCode(), p2.HashCode())
}

func TestModuleValuedPolynomialString(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	p, _ := polyMod.New(g.Clone())
	str := p.String()
	require.Contains(t, str, "[")
	require.Contains(t, str, "]")
}

func TestModuleValuedPolynomialStructure(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	p, _ := polyMod.New(g.Clone())
	structure := p.Structure()
	require.NotNil(t, structure)
}

func TestModuleValuedPolynomialCoefficientStructure(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	p, _ := polyMod.New(g.Clone())
	coeffStruct := p.CoefficientStructure()
	require.NotNil(t, coeffStruct)
}

func TestModuleValuedPolynomialScalarStructure(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	p, _ := polyMod.New(g.Clone())
	scalarStruct := p.ScalarStructure()
	require.NotNil(t, scalarStruct)
}

func TestModuleValuedPolynomialIsTorsionFree(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyMod, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	g := curve.Generator()

	p, _ := polyMod.New(g.Clone())
	// Polynomial over points (which are torsion-free over a field) should be torsion-free
	require.True(t, p.IsTorsionFree())
}

func TestLiftPolynomial(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)
	g := curve.Generator()

	t.Run("lift scalar polynomial to module-valued polynomial", func(t *testing.T) {
		one := field.One()
		two := field.FromUint64(2)
		scalarPoly, _ := polyRing.New(one.Clone(), two.Clone()) // 1 + 2x

		mvp, err := polynomials.LiftPolynomial(scalarPoly, g)
		require.NoError(t, err)

		// (1 + 2x) * G = G + 2Gx
		require.Equal(t, scalarPoly.Degree(), mvp.Degree())
		require.True(t, mvp.ConstantTerm().Equal(g))
		require.True(t, mvp.Coefficients()[1].Equal(g.Double()))
	})
}
