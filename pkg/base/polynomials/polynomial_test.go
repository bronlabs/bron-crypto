package polynomials_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

func TestPolynomialEuclideanDiv(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	zero := field.Zero()

	dividend, err := polyRing.New(one.Clone(), one.Clone(), one.Clone()) // x^2 + x + 1
	require.NoError(t, err)
	divisor, err := polyRing.New(one.Clone(), one.Clone()) // x + 1
	require.NoError(t, err)

	quot, rem, err := dividend.EuclideanDiv(divisor)
	require.NoError(t, err)

	expectedQuot, err := polyRing.New(zero.Clone(), one.Clone()) // x
	require.NoError(t, err)
	expectedRem, err := polyRing.New(one.Clone()) // 1
	require.NoError(t, err)

	require.True(t, quot.Equal(expectedQuot))
	require.True(t, rem.Equal(expectedRem))
}

func TestPolynomialEuclideanDivDegreeLess(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	zero := field.Zero()

	dividend, err := polyRing.New(one.Clone(), one.Clone()) // x + 1
	require.NoError(t, err)
	divisor, err := polyRing.New(one.Clone(), one.Clone(), one.Clone()) // x^2 + x + 1
	require.NoError(t, err)

	quot, rem, err := dividend.EuclideanDiv(divisor)
	require.NoError(t, err)

	expectedQuot, err := polyRing.New(zero.Clone())
	require.NoError(t, err)

	require.True(t, quot.Equal(expectedQuot))
	require.True(t, rem.Equal(dividend))
}

func TestPolynomialEuclideanDivByZero(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	dividend, err := polyRing.New(one.Clone(), one.Clone())
	require.NoError(t, err)

	_, _, err = dividend.EuclideanDiv(polyRing.Zero())
	require.Error(t, err)
}

func TestPolynomialRingNew(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	t.Run("empty coefficients returns zero polynomial", func(t *testing.T) {
		t.Parallel()
		poly, err := polyRing.New()
		require.NoError(t, err)
		require.True(t, poly.IsZero())
		require.Equal(t, -1, poly.Degree())
	})

	t.Run("single coefficient", func(t *testing.T) {
		t.Parallel()
		one := field.One()
		poly, err := polyRing.New(one)
		require.NoError(t, err)
		require.Equal(t, 0, poly.Degree())
		require.True(t, poly.ConstantTerm().Equal(one))
	})

	t.Run("multiple coefficients", func(t *testing.T) {
		t.Parallel()
		one := field.One()
		two := field.FromUint64(2)
		three := field.FromUint64(3)
		poly, err := polyRing.New(one, two, three) // 1 + 2x + 3x^2
		require.NoError(t, err)
		require.Equal(t, 2, poly.Degree())
		coeffs := poly.Coefficients()
		require.Len(t, coeffs, 3)
		require.True(t, coeffs[0].Equal(one))
		require.True(t, coeffs[1].Equal(two))
		require.True(t, coeffs[2].Equal(three))
	})

	t.Run("nil coefficient returns error", func(t *testing.T) {
		t.Parallel()
		one := field.One()
		_, err := polyRing.New(one, nil, one)
		require.Error(t, err)
	})
}

func TestPolynomialRingZeroAndOne(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	t.Run("zero polynomial", func(t *testing.T) {
		t.Parallel()
		zero := polyRing.Zero()
		require.True(t, zero.IsZero())
		require.True(t, zero.IsOpIdentity())
		require.Equal(t, -1, zero.Degree())
	})

	t.Run("one polynomial", func(t *testing.T) {
		t.Parallel()
		one := polyRing.One()
		require.True(t, one.IsOne())
		require.False(t, one.IsZero())
		require.Equal(t, 0, one.Degree())
	})

	t.Run("OpIdentity is zero", func(t *testing.T) {
		t.Parallel()
		require.True(t, polyRing.OpIdentity().Equal(polyRing.Zero()))
	})
}

func TestPolynomialRingName(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)
	require.Contains(t, polyRing.Name(), "PolynomialRing")
}

func TestPolynomialRingElementSize(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)
	// Variable-length element, returns -1
	require.Equal(t, -1, polyRing.ElementSize())
}

func TestPolynomialRingFromBytes(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	t.Run("roundtrip", func(t *testing.T) {
		t.Parallel()
		one := field.One()
		two := field.FromUint64(2)
		original, err := polyRing.New(one, two)
		require.NoError(t, err)

		bytes := original.Bytes()
		recovered, err := polyRing.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, original.Equal(recovered))
	})

	t.Run("empty bytes returns error", func(t *testing.T) {
		t.Parallel()
		_, err := polyRing.FromBytes([]byte{})
		require.Error(t, err)
	})

	t.Run("invalid length returns error", func(t *testing.T) {
		t.Parallel()
		_, err := polyRing.FromBytes([]byte{1, 2, 3})
		require.Error(t, err)
	})
}

func TestPolynomialAdd(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)
	three := field.FromUint64(3)

	t.Run("same degree", func(t *testing.T) {
		t.Parallel()
		p1, _ := polyRing.New(one.Clone(), two.Clone())   // 1 + 2x
		p2, _ := polyRing.New(two.Clone(), three.Clone()) // 2 + 3x
		sum := p1.Add(p2)                                 // 3 + 5x
		expected, _ := polyRing.New(three.Clone(), field.FromUint64(5))
		require.True(t, sum.Equal(expected))
	})

	t.Run("different degrees", func(t *testing.T) {
		t.Parallel()
		p1, _ := polyRing.New(one.Clone())                             // 1
		p2, _ := polyRing.New(two.Clone(), three.Clone(), one.Clone()) // 2 + 3x + x^2
		sum := p1.Add(p2)                                              // 3 + 3x + x^2
		expected, _ := polyRing.New(three.Clone(), three.Clone(), one.Clone())
		require.True(t, sum.Equal(expected))
	})

	t.Run("add zero", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		sum := p.Add(polyRing.Zero())
		require.True(t, sum.Equal(p))
	})

	t.Run("Op is Add", func(t *testing.T) {
		t.Parallel()
		p1, _ := polyRing.New(one.Clone(), two.Clone())
		p2, _ := polyRing.New(three.Clone())
		require.True(t, p1.Add(p2).Equal(p1.Op(p2)))
	})
}

func TestPolynomialMul(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)

	t.Run("multiply constants", func(t *testing.T) {
		t.Parallel()
		p1, _ := polyRing.New(two.Clone())
		p2, _ := polyRing.New(field.FromUint64(3))
		prod := p1.Mul(p2)
		expected, _ := polyRing.New(field.FromUint64(6))
		require.True(t, prod.Equal(expected))
	})

	t.Run("multiply by x+1", func(t *testing.T) {
		t.Parallel()
		// (x + 1) * (x + 1) = x^2 + 2x + 1
		xPlusOne, _ := polyRing.New(one.Clone(), one.Clone())
		result := xPlusOne.Mul(xPlusOne)
		expected, _ := polyRing.New(one.Clone(), two.Clone(), one.Clone())
		require.True(t, result.Equal(expected))
	})

	t.Run("multiply by zero", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		result := p.Mul(polyRing.Zero())
		require.True(t, result.IsZero())
	})

	t.Run("multiply by one", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		result := p.Mul(polyRing.One())
		require.True(t, result.Equal(p))
	})

	t.Run("OtherOp is Mul", func(t *testing.T) {
		t.Parallel()
		p1, _ := polyRing.New(one.Clone(), two.Clone())
		p2, _ := polyRing.New(one.Clone(), one.Clone())
		require.True(t, p1.Mul(p2).Equal(p1.OtherOp(p2)))
	})
}

func TestPolynomialSub(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)
	three := field.FromUint64(3)

	t.Run("subtraction", func(t *testing.T) {
		t.Parallel()
		p1, _ := polyRing.New(three.Clone(), two.Clone()) // 3 + 2x
		p2, _ := polyRing.New(one.Clone(), one.Clone())   // 1 + x
		diff := p1.Sub(p2)                                // 2 + x
		expected, _ := polyRing.New(two.Clone(), one.Clone())
		require.True(t, diff.Equal(expected))
	})

	t.Run("self subtraction is zero", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		diff := p.Sub(p)
		require.True(t, diff.IsZero())
	})
}

func TestPolynomialNeg(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)

	t.Run("negation", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		neg := p.Neg()
		// p + neg(p) = 0
		require.True(t, p.Add(neg).IsZero())
	})

	t.Run("OpInv is Neg", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		require.True(t, p.Neg().Equal(p.OpInv()))
	})

	t.Run("TryNeg succeeds", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone())
		neg, err := p.TryNeg()
		require.NoError(t, err)
		require.True(t, neg.Equal(p.Neg()))
	})

	t.Run("TryOpInv succeeds", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone())
		inv, err := p.TryOpInv()
		require.NoError(t, err)
		require.True(t, inv.Equal(p.Neg()))
	})
}

func TestPolynomialDegree(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	zero := field.Zero()

	t.Run("zero polynomial has degree -1", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, -1, polyRing.Zero().Degree())
	})

	t.Run("constant has degree 0", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone())
		require.Equal(t, 0, p.Degree())
	})

	t.Run("linear has degree 1", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), one.Clone())
		require.Equal(t, 1, p.Degree())
	})

	t.Run("trailing zeros ignored", func(t *testing.T) {
		t.Parallel()
		// Polynomial with coefficients [1, 2, 0] has degree 1
		p, _ := polyRing.New(one.Clone(), field.FromUint64(2), zero.Clone())
		require.Equal(t, 1, p.Degree())
	})
}

func TestPolynomialConstantTerm(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)
	three := field.FromUint64(3)

	p, _ := polyRing.New(one.Clone(), two.Clone(), three.Clone())
	require.True(t, p.ConstantTerm().Equal(one))
}

func TestPolynomialLeadingCoefficient(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)
	three := field.FromUint64(3)

	t.Run("non-zero polynomial", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone(), three.Clone())
		require.True(t, p.LeadingCoefficient().Equal(three))
	})

	t.Run("zero polynomial returns zero", func(t *testing.T) {
		t.Parallel()
		require.True(t, polyRing.Zero().LeadingCoefficient().IsZero())
	})

	t.Run("trailing zeros handled", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone(), field.Zero())
		require.True(t, p.LeadingCoefficient().Equal(two))
	})
}

func TestPolynomialIsConstant(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)

	t.Run("constant is constant", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone())
		require.True(t, p.IsConstant())
	})

	t.Run("zero is not constant (degree -1)", func(t *testing.T) {
		t.Parallel()
		require.False(t, polyRing.Zero().IsConstant())
	})

	t.Run("linear is not constant", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		require.False(t, p.IsConstant())
	})
}

func TestPolynomialIsMonic(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)

	t.Run("monic polynomial", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(two.Clone(), one.Clone()) // 2 + x
		require.True(t, p.IsMonic())
	})

	t.Run("non-monic polynomial", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone()) // 1 + 2x
		require.False(t, p.IsMonic())
	})

	t.Run("zero is not monic", func(t *testing.T) {
		t.Parallel()
		require.False(t, polyRing.Zero().IsMonic())
	})

	t.Run("one is monic", func(t *testing.T) {
		t.Parallel()
		require.True(t, polyRing.One().IsMonic())
	})
}

func TestPolynomialEval(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)
	three := field.FromUint64(3)

	t.Run("eval at zero gives constant term", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(two.Clone(), three.Clone(), one.Clone()) // 2 + 3x + x^2
		result := p.Eval(field.Zero())
		require.True(t, result.Equal(two))
	})

	t.Run("eval at one sums coefficients", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone(), three.Clone()) // 1 + 2x + 3x^2
		result := p.Eval(one.Clone())
		expected := field.FromUint64(6) // 1 + 2 + 3
		require.True(t, result.Equal(expected))
	})

	t.Run("eval linear polynomial", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone()) // 1 + 2x
		result := p.Eval(three.Clone())                // 1 + 2*3 = 7
		expected := field.FromUint64(7)
		require.True(t, result.Equal(expected))
	})

	t.Run("eval quadratic polynomial", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone(), three.Clone()) // 1 + 2x + 3x^2
		result := p.Eval(two.Clone())                                 // 1 + 2*2 + 3*4 = 1 + 4 + 12 = 17
		expected := field.FromUint64(17)
		require.True(t, result.Equal(expected))
	})

	t.Run("eval zero polynomial", func(t *testing.T) {
		t.Parallel()
		result := polyRing.Zero().Eval(three.Clone())
		require.True(t, result.IsZero())
	})
}

func TestPolynomialDerivative(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)
	three := field.FromUint64(3)

	t.Run("constant derivative is zero", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(three.Clone())
		deriv := p.Derivative()
		require.True(t, deriv.IsZero())
	})

	t.Run("linear derivative is constant", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone()) // 1 + 2x
		deriv := p.Derivative()                        // 2
		expected, _ := polyRing.New(two.Clone())
		require.True(t, deriv.Equal(expected))
	})

	t.Run("quadratic derivative", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone(), three.Clone()) // 1 + 2x + 3x^2
		deriv := p.Derivative()                                       // 2 + 6x
		expected, _ := polyRing.New(two.Clone(), field.FromUint64(6))
		require.True(t, deriv.Equal(expected))
	})

	t.Run("derivative reduces degree", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone(), three.Clone(), one.Clone()) // degree 3
		deriv := p.Derivative()
		require.Equal(t, 2, deriv.Degree())
	})

	t.Run("zero derivative is zero", func(t *testing.T) {
		t.Parallel()
		deriv := polyRing.Zero().Derivative()
		require.True(t, deriv.IsZero())
	})
}

func TestPolynomialScalarMul(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)
	three := field.FromUint64(3)

	t.Run("scalar multiply", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone()) // 1 + 2x
		result := p.ScalarMul(three.Clone())           // 3 + 6x
		expected, _ := polyRing.New(three.Clone(), field.FromUint64(6))
		require.True(t, result.Equal(expected))
	})

	t.Run("multiply by zero", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		result := p.ScalarMul(field.Zero())
		require.True(t, result.IsZero())
	})

	t.Run("multiply by one", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		result := p.ScalarMul(one.Clone())
		require.True(t, result.Equal(p))
	})

	t.Run("ScalarOp is ScalarMul", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), two.Clone())
		require.True(t, p.ScalarMul(three).Equal(p.ScalarOp(three)))
	})
}

func TestPolynomialDouble(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)

	p, _ := polyRing.New(one.Clone(), two.Clone())
	doubled := p.Double()
	expected := p.Add(p)
	require.True(t, doubled.Equal(expected))
}

func TestPolynomialSquare(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)

	p, _ := polyRing.New(one.Clone(), two.Clone())
	squared := p.Square()
	expected := p.Mul(p)
	require.True(t, squared.Equal(expected))
}

func TestPolynomialClone(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)

	original, _ := polyRing.New(one.Clone(), two.Clone())
	clone := original.Clone()

	require.True(t, original.Equal(clone))

	// Verify deep copy
	coeffs := clone.Coefficients()
	require.True(t, coeffs[0].Equal(one))
}

func TestPolynomialEqual(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)
	zero := field.Zero()

	t.Run("equal polynomials", func(t *testing.T) {
		t.Parallel()
		p1, _ := polyRing.New(one.Clone(), two.Clone())
		p2, _ := polyRing.New(one.Clone(), two.Clone())
		require.True(t, p1.Equal(p2))
	})

	t.Run("unequal polynomials", func(t *testing.T) {
		t.Parallel()
		p1, _ := polyRing.New(one.Clone(), two.Clone())
		p2, _ := polyRing.New(two.Clone(), one.Clone())
		require.False(t, p1.Equal(p2))
	})

	t.Run("different degrees with trailing zeros", func(t *testing.T) {
		t.Parallel()
		p1, _ := polyRing.New(one.Clone(), two.Clone())
		p2, _ := polyRing.New(one.Clone(), two.Clone(), zero.Clone())
		require.True(t, p1.Equal(p2))
	})
}

func TestPolynomialHashCode(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)

	p1, _ := polyRing.New(one.Clone(), two.Clone())
	p2, _ := polyRing.New(one.Clone(), two.Clone())

	// Equal polynomials should have equal hash codes
	require.Equal(t, p1.HashCode(), p2.HashCode())
}

func TestPolynomialString(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	p, _ := polyRing.New(one.Clone())
	str := p.String()
	require.Contains(t, str, "[")
	require.Contains(t, str, "]")
}

func TestPolynomialStructure(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	p, _ := polyRing.New(one.Clone())

	structure := p.Structure()
	require.NotNil(t, structure)
}

func TestPolynomialCoefficientStructure(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	p, _ := polyRing.New(one.Clone())

	coeffStruct := p.CoefficientStructure()
	require.NotNil(t, coeffStruct)
}

func TestPolynomialScalarStructure(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	p, _ := polyRing.New(one.Clone())

	scalarStruct := p.ScalarStructure()
	require.NotNil(t, scalarStruct)
}

func TestPolynomialIsTorsionFree(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	p, _ := polyRing.New(one.Clone())

	// Polynomial over a field is torsion-free
	require.True(t, p.IsTorsionFree())
}

func TestPolynomialTryInvAndTryDiv(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	p, _ := polyRing.New(one.Clone(), one.Clone())

	t.Run("TryInv not supported", func(t *testing.T) {
		t.Parallel()
		_, err := p.TryInv()
		require.Error(t, err)
	})

	t.Run("TryDiv not supported", func(t *testing.T) {
		t.Parallel()
		_, err := p.TryDiv(polyRing.One())
		require.Error(t, err)
	})
}

func TestPolynomialTrySub(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	two := field.FromUint64(2)

	p1, _ := polyRing.New(two.Clone())
	p2, _ := polyRing.New(one.Clone())

	result, err := p1.TrySub(p2)
	require.NoError(t, err)
	expected, _ := polyRing.New(one.Clone())
	require.True(t, result.Equal(expected))
}

func TestPolynomialEuclideanValuation(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()

	t.Run("zero polynomial", func(t *testing.T) {
		t.Parallel()
		val := polyRing.Zero().EuclideanValuation()
		require.True(t, val.IsFinite())
	})

	t.Run("constant polynomial", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone())
		val := p.EuclideanValuation()
		require.True(t, val.IsFinite())
	})

	t.Run("linear polynomial", func(t *testing.T) {
		t.Parallel()
		p, _ := polyRing.New(one.Clone(), one.Clone())
		val := p.EuclideanValuation()
		require.True(t, val.IsFinite())
	})
}

func TestPolynomialRingCharacteristic(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	char := polyRing.Characteristic()
	require.True(t, char.Equal(field.Characteristic()))
}

func TestPolynomialRingOrder(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	order := polyRing.Order()
	require.False(t, order.IsFinite())
}

func TestPolynomialRingIsDomain(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	require.True(t, polyRing.IsDomain())
}

func TestPolynomialRingScalarStructure(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	scalarStruct := polyRing.ScalarStructure()
	require.NotNil(t, scalarStruct)
}
