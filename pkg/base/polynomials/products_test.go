package polynomials_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// =========== DirectSumOfPolynomialRings ===========

func TestNewDirectSumOfPolynomialRings(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		t.Parallel()
		dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 3)
		require.NoError(t, err)
		require.NotNil(t, dsum)
	})

	t.Run("Arity zero", func(t *testing.T) {
		t.Parallel()
		dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 0)
		require.Error(t, err)
		require.Nil(t, dsum)
	})

	t.Run("Nil polyRing", func(t *testing.T) {
		t.Parallel()
		dsum, err := polynomials.NewDirectSumOfPolynomialRings[*k256.Scalar](nil, 2)
		require.Error(t, err)
		require.Nil(t, dsum)
	})
}

func TestDirectSumOfPolynomialRingsNew(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)
	require.NoError(t, err)

	p1, _ := polyRing.New(field.FromUint64(1), field.FromUint64(2)) // 1 + 2x
	p2, _ := polyRing.New(field.FromUint64(3))                      // 3

	t.Run("Valid components", func(t *testing.T) {
		t.Parallel()
		elem, err := dsum.New(p1, p2)
		require.NoError(t, err)
		require.NotNil(t, elem)
		require.Len(t, elem.Components(), 2)
		require.True(t, elem.Components()[0].Equal(p1))
		require.True(t, elem.Components()[1].Equal(p2))
	})

	t.Run("Wrong arity", func(t *testing.T) {
		t.Parallel()
		_, err := dsum.New(p1)
		require.Error(t, err)
	})
}

func TestDirectSumOfPolynomialRingsCoefficientAlgebra(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 3)
	require.NoError(t, err)

	coeffAlg := dsum.CoefficientAlgebra()
	require.NotNil(t, coeffAlg)
}

// =========== DirectSumOfPolynomials ===========

func TestDirectSumOfPolynomialsStructure(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)
	require.NoError(t, err)

	p1, _ := polyRing.New(field.FromUint64(1), field.FromUint64(2))
	p2, _ := polyRing.New(field.FromUint64(3))

	elem, err := dsum.New(p1, p2)
	require.NoError(t, err)

	s := elem.Structure()
	require.NotNil(t, s)
	require.Equal(t, dsum.Name(), s.Name())
}

func TestDirectSumOfPolynomialsIsDomain(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)
	require.NoError(t, err)
	// Direct sums are never domains
	require.False(t, dsum.IsDomain())
}

func TestDirectSumOfPolynomialsCoefficientAlgebra(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)
	require.NoError(t, err)

	p1, _ := polyRing.New(field.FromUint64(1))
	p2, _ := polyRing.New(field.FromUint64(2))
	elem, _ := dsum.New(p1, p2)

	coeffAlg := elem.CoefficientAlgebra()
	require.NotNil(t, coeffAlg)
}

func TestDirectSumOfPolynomialsRegulariseScalars(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)
	require.NoError(t, err)

	p1, _ := polyRing.New(field.FromUint64(1))
	p2, _ := polyRing.New(field.FromUint64(2))
	elem, _ := dsum.New(p1, p2)

	t.Run("Valid", func(t *testing.T) {
		t.Parallel()
		result, err := elem.RegulariseScalars(field.FromUint64(5), field.FromUint64(7))
		require.NoError(t, err)
		require.Len(t, result, 2)
		require.True(t, result[0].Value().Equal(field.FromUint64(5)))
		require.True(t, result[1].Value().Equal(field.FromUint64(7)))
	})

	t.Run("Wrong count", func(t *testing.T) {
		t.Parallel()
		_, err := elem.RegulariseScalars(field.FromUint64(5))
		require.Error(t, err)
		require.Contains(t, err.Error(), "incorrect component count")
	})
}

func TestDirectSumOfPolynomialsEval(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)
	require.NoError(t, err)

	// p1 = 1 + 2x, p2 = 3 + 4x
	p1, _ := polyRing.New(field.FromUint64(1), field.FromUint64(2))
	p2, _ := polyRing.New(field.FromUint64(3), field.FromUint64(4))
	elem, _ := dsum.New(p1, p2)

	t.Run("Eval at zero", func(t *testing.T) {
		t.Parallel()
		result := elem.Eval(field.Zero())
		// p1(0)=1, p2(0)=3
		require.True(t, result.Components()[0].Value().Equal(field.FromUint64(1)))
		require.True(t, result.Components()[1].Value().Equal(field.FromUint64(3)))
	})

	t.Run("Eval at one", func(t *testing.T) {
		t.Parallel()
		result := elem.Eval(field.One())
		// p1(1)=1+2=3, p2(1)=3+4=7
		require.True(t, result.Components()[0].Value().Equal(field.FromUint64(3)))
		require.True(t, result.Components()[1].Value().Equal(field.FromUint64(7)))
	})

	t.Run("Eval at arbitrary point", func(t *testing.T) {
		t.Parallel()
		result := elem.Eval(field.FromUint64(5))
		// p1(5)=1+10=11, p2(5)=3+20=23
		require.True(t, result.Components()[0].Value().Equal(field.FromUint64(11)))
		require.True(t, result.Components()[1].Value().Equal(field.FromUint64(23)))
	})
}

func TestDirectSumOfPolynomialsOp(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)
	require.NoError(t, err)

	p1, _ := polyRing.New(field.FromUint64(1), field.FromUint64(2))
	p2, _ := polyRing.New(field.FromUint64(3))
	p3, _ := polyRing.New(field.FromUint64(4), field.FromUint64(5))
	p4, _ := polyRing.New(field.FromUint64(6))

	elem1, _ := dsum.New(p1, p2)
	elem2, _ := dsum.New(p3, p4)

	t.Run("Component-wise addition", func(t *testing.T) {
		t.Parallel()
		result := elem1.Op(elem2)
		// (1+2x)+(4+5x) = 5+7x, 3+6 = 9
		require.True(t, result.Components()[0].Equal(p1.Add(p3)))
		require.True(t, result.Components()[1].Equal(p2.Add(p4)))
	})

	t.Run("OpInv", func(t *testing.T) {
		t.Parallel()
		inv := elem1.OpInv()
		result := elem1.Op(inv)
		require.True(t, result.IsOpIdentity())
	})
}

func TestDirectSumOfPolynomialsScalarOp(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)
	require.NoError(t, err)

	// p1 = 1 + 2x, p2 = 3
	p1, _ := polyRing.New(field.FromUint64(1), field.FromUint64(2))
	p2, _ := polyRing.New(field.FromUint64(3))
	elem, _ := dsum.New(p1, p2)

	scalar := field.FromUint64(5)
	result := elem.ScalarOp(scalar)

	// 5*(1+2x) = 5+10x, 5*3 = 15
	require.True(t, result.Components()[0].Equal(p1.ScalarMul(scalar)))
	require.True(t, result.Components()[1].Equal(p2.ScalarMul(scalar)))
}

// =========== DirectSumOfPolynomialModules ===========

func TestNewDirectSumOfPolynomialModules(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		t.Parallel()
		dsum, err := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)
		require.NoError(t, err)
		require.NotNil(t, dsum)
	})

	t.Run("Arity zero", func(t *testing.T) {
		t.Parallel()
		dsum, err := polynomials.NewDirectSumOfPolynomialModules(polyModule, 0)
		require.Error(t, err)
		require.Nil(t, dsum)
	})

	t.Run("Nil polyModule", func(t *testing.T) {
		t.Parallel()
		dsum, err := polynomials.NewDirectSumOfPolynomialModules[*k256.Point, *k256.Scalar](nil, 2)
		require.Error(t, err)
		require.Nil(t, dsum)
	})
}

func TestDirectSumOfPolynomialModulesLift(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)
	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)
	require.NoError(t, err)

	gen := curve.Generator()
	gen2 := gen.Double()

	p1, _ := polyRing.New(field.FromUint64(1), field.FromUint64(2)) // 1 + 2x
	p2, _ := polyRing.New(field.FromUint64(3))                      // 3

	t.Run("Valid lift", func(t *testing.T) {
		t.Parallel()
		lifted, err := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p1, p2}, gen, gen2)
		require.NoError(t, err)
		require.NotNil(t, lifted)
		require.Len(t, lifted.Components(), 2)

		// First component: (1+2x)*G = G + 2G*x
		require.True(t, lifted.Components()[0].ConstantTerm().Equal(gen))
		require.True(t, lifted.Components()[0].Coefficients()[1].Equal(gen.Double()))

		// Second component: 3*2G = 6G
		sixG := gen2.ScalarOp(field.FromUint64(3))
		require.True(t, lifted.Components()[1].ConstantTerm().Equal(sixG))
	})

	t.Run("Wrong polynomial count", func(t *testing.T) {
		t.Parallel()
		_, err := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p1}, gen, gen2)
		require.Error(t, err)
		require.Contains(t, err.Error(), "polynomial count does not match arity")
	})

	t.Run("Wrong base points count", func(t *testing.T) {
		t.Parallel()
		_, err := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p1, p2}, gen)
		require.Error(t, err)
		require.Contains(t, err.Error(), "base points count does not match arity")
	})
}

func TestDirectSumOfPolynomialModulesCoefficientModule(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)
	require.NoError(t, err)

	coeffMod := dsum.CoefficientModule()
	require.NotNil(t, coeffMod)
}

func TestDirectSumOfPolynomialModulesBaseAlgebra(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	dsum, err := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)
	require.NoError(t, err)

	baseAlg := dsum.BaseAlgebra()
	require.NotNil(t, baseAlg)
}

// =========== DirectSumOfModuleValuedPolynomials ===========

func TestDirectSumOfModuleValuedPolynomialsStructure(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, _ := polynomials.NewPolynomialRing(field)
	polyModule, _ := polynomials.NewPolynomialModule(curve)

	dsum, _ := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)

	gen := curve.Generator()
	p1, _ := polyRing.New(field.FromUint64(1), field.FromUint64(2))
	p2, _ := polyRing.New(field.FromUint64(3))

	elem, err := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p1, p2}, gen, gen)
	require.NoError(t, err)

	s := elem.Structure()
	require.NotNil(t, s)
	require.Equal(t, dsum.Name(), s.Name())
}

func TestDirectSumOfModuleValuedPolynomialsCoefficientModule(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, _ := polynomials.NewPolynomialRing(field)
	polyModule, _ := polynomials.NewPolynomialModule(curve)

	dsum, _ := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)

	gen := curve.Generator()
	p1, _ := polyRing.New(field.FromUint64(1))
	p2, _ := polyRing.New(field.FromUint64(2))

	elem, err := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p1, p2}, gen, gen)
	require.NoError(t, err)

	coeffMod := elem.CoefficientModule()
	require.NotNil(t, coeffMod)
}

func TestDirectSumOfModuleValuedPolynomialsBaseRing(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, _ := polynomials.NewPolynomialRing(field)
	polyModule, _ := polynomials.NewPolynomialModule(curve)

	dsum, _ := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)

	gen := curve.Generator()
	p1, _ := polyRing.New(field.FromUint64(1))
	p2, _ := polyRing.New(field.FromUint64(2))

	elem, err := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p1, p2}, gen, gen)
	require.NoError(t, err)

	baseRing := elem.BaseRing()
	require.NotNil(t, baseRing)
}

func TestDirectSumOfModuleValuedPolynomialsEval(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, _ := polynomials.NewPolynomialRing(field)
	polyModule, _ := polynomials.NewPolynomialModule(curve)

	dsum, _ := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)

	gen := curve.Generator()
	// p1 = 1 + 2x, p2 = 3
	p1, _ := polyRing.New(field.FromUint64(1), field.FromUint64(2))
	p2, _ := polyRing.New(field.FromUint64(3))

	elem, err := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p1, p2}, gen, gen)
	require.NoError(t, err)

	t.Run("Eval at zero", func(t *testing.T) {
		t.Parallel()
		result := elem.Eval(field.Zero())
		// component 0: (1+2*0)*G = G
		// component 1: 3*G = 3G
		require.True(t, result.Components()[0].Equal(gen))
		threeG := gen.ScalarOp(field.FromUint64(3))
		require.True(t, result.Components()[1].Equal(threeG))
	})

	t.Run("Eval at one", func(t *testing.T) {
		t.Parallel()
		result := elem.Eval(field.One())
		// component 0: (1+2)*G = 3G
		// component 1: 3*G = 3G
		threeG := gen.ScalarOp(field.FromUint64(3))
		require.True(t, result.Components()[0].Equal(threeG))
		require.True(t, result.Components()[1].Equal(threeG))
	})

	t.Run("Eval at arbitrary point", func(t *testing.T) {
		t.Parallel()
		result := elem.Eval(field.FromUint64(5))
		// component 0: (1+10)*G = 11G
		// component 1: 3*G = 3G
		elevenG := gen.ScalarOp(field.FromUint64(11))
		threeG := gen.ScalarOp(field.FromUint64(3))
		require.True(t, result.Components()[0].Equal(elevenG))
		require.True(t, result.Components()[1].Equal(threeG))
	})
}

func TestDirectSumOfModuleValuedPolynomialsOp(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, _ := polynomials.NewPolynomialRing(field)
	polyModule, _ := polynomials.NewPolynomialModule(curve)

	dsum, _ := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)

	gen := curve.Generator()
	p1, _ := polyRing.New(field.FromUint64(1))
	p2, _ := polyRing.New(field.FromUint64(2))
	p3, _ := polyRing.New(field.FromUint64(3))
	p4, _ := polyRing.New(field.FromUint64(4))

	elem1, _ := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p1, p2}, gen, gen)
	elem2, _ := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p3, p4}, gen, gen)

	t.Run("Component-wise addition", func(t *testing.T) {
		t.Parallel()
		result := elem1.Op(elem2)
		// At x=0: component 0: 1*G + 3*G = 4G, component 1: 2*G + 4*G = 6G
		evalResult := result.Eval(field.Zero())
		fourG := gen.ScalarOp(field.FromUint64(4))
		sixG := gen.ScalarOp(field.FromUint64(6))
		require.True(t, evalResult.Components()[0].Equal(fourG))
		require.True(t, evalResult.Components()[1].Equal(sixG))
	})

	t.Run("OpInv", func(t *testing.T) {
		t.Parallel()
		inv := elem1.OpInv()
		result := elem1.Op(inv)
		require.True(t, result.IsOpIdentity())
	})
}

func TestDirectSumOfModuleValuedPolynomialsScalarOp(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, _ := polynomials.NewPolynomialRing(field)
	polyModule, _ := polynomials.NewPolynomialModule(curve)

	dsum, _ := polynomials.NewDirectSumOfPolynomialModules(polyModule, 2)

	gen := curve.Generator()
	p1, _ := polyRing.New(field.FromUint64(2))
	p2, _ := polyRing.New(field.FromUint64(3))

	elem, _ := dsum.Lift([]*polynomials.Polynomial[*k256.Scalar]{p1, p2}, gen, gen)

	scalar := field.FromUint64(5)
	result := elem.ScalarOp(scalar)

	// At x=0: component 0: 5*(2*G) = 10G, component 1: 5*(3*G) = 15G
	evalResult := result.Eval(field.Zero())
	tenG := gen.ScalarOp(field.FromUint64(10))
	fifteenG := gen.ScalarOp(field.FromUint64(15))
	require.True(t, evalResult.Components()[0].Equal(tenG))
	require.True(t, evalResult.Components()[1].Equal(fifteenG))
}

// =========== LiftDirectSumOfPolynomialsToExponent ===========

func TestLiftDirectSumOfPolynomialsToExponent(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, _ := polynomials.NewPolynomialRing(field)

	gen := curve.Generator()
	gen2 := gen.Double()

	// Build a DirectSumOfPolynomials with 2 scalar polynomials
	dsumRings, err := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)
	require.NoError(t, err)

	p1, _ := polyRing.New(field.FromUint64(1), field.FromUint64(2)) // 1 + 2x
	p2, _ := polyRing.New(field.FromUint64(3), field.FromUint64(4)) // 3 + 4x
	dsum, _ := dsumRings.New(p1, p2)

	t.Run("Valid lift", func(t *testing.T) {
		t.Parallel()
		lifted, err := polynomials.LiftDirectSumOfPolynomialsToExponent(dsum, gen, gen2)
		require.NoError(t, err)
		require.NotNil(t, lifted)
		require.Len(t, lifted.Components(), 2)

		// Eval at x=0: component 0: 1*G = G, component 1: 3*2G = 6G
		result := lifted.Eval(field.Zero())
		sixG := gen.ScalarOp(field.FromUint64(6))
		require.True(t, result.Components()[0].Equal(gen))
		require.True(t, result.Components()[1].Equal(sixG))

		// Eval at x=1: component 0: (1+2)*G = 3G, component 1: (3+4)*2G = 14G
		result = lifted.Eval(field.One())
		threeG := gen.ScalarOp(field.FromUint64(3))
		fourteenG := gen.ScalarOp(field.FromUint64(14))
		require.True(t, result.Components()[0].Equal(threeG))
		require.True(t, result.Components()[1].Equal(fourteenG))
	})

	t.Run("Nil dsum", func(t *testing.T) {
		t.Parallel()
		_, err := polynomials.LiftDirectSumOfPolynomialsToExponent[*k256.Point, *k256.Scalar](nil, gen)
		require.Error(t, err)
		require.Contains(t, err.Error(), "dsum is nil")
	})

	t.Run("Empty base points", func(t *testing.T) {
		t.Parallel()
		_, err := polynomials.LiftDirectSumOfPolynomialsToExponent[*k256.Point](dsum)
		require.Error(t, err)
		require.Contains(t, err.Error(), "base points must not be empty")
	})
}

// =========== Eval consistency: scalar eval then lift vs. lift then eval ===========

func TestEvalLiftConsistency(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	polyRing, _ := polynomials.NewPolynomialRing(field)

	gen := curve.Generator()
	prng := pcg.NewRandomised()

	dsumRings, _ := polynomials.NewDirectSumOfPolynomialRings(polyRing, 2)

	p1, _ := polyRing.RandomPolynomial(3, prng)
	p2, _ := polyRing.RandomPolynomial(2, prng)
	dsum, _ := dsumRings.New(p1, p2)

	point, _ := field.Random(prng)

	// Lift then eval
	lifted, err := polynomials.LiftDirectSumOfPolynomialsToExponent(dsum, gen, gen)
	require.NoError(t, err)
	liftThenEval := lifted.Eval(point)

	// Scalar eval then lift to module elements
	scalarEval := dsum.Eval(point)
	v0 := gen.ScalarOp(scalarEval.Components()[0].Value())
	v1 := gen.ScalarOp(scalarEval.Components()[1].Value())

	require.True(t, liftThenEval.Components()[0].Equal(v0))
	require.True(t, liftThenEval.Components()[1].Equal(v1))
}
