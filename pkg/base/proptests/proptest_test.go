package proptests

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/proptests/rapidext"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func Test_FieldAdditivelyCommutative(t *testing.T) {
	t.Run("k256 base field", func(t *testing.T) {
		field := k256.NewBaseField()
		testFieldAdditivelyCommutative(t, field)
	})
	t.Run("k256 scalar field", func(t *testing.T) {
		field := k256.NewScalarField()
		testFieldAdditivelyCommutative(t, field)
	})
}

func testFieldAdditivelyCommutative[FE algebra.FiniteFieldElement[FE]](t *testing.T, field algebra.FiniteField[FE]) {
	rapid.Check(t, func(t *rapid.T) {
		gen := rapidext.UniformDomainElement(field)
		x := gen.Draw(t, "x")
		y := gen.Draw(t, "y")
		require.True(t, x.Add(y).Equal(y.Add(x)))
	})
}
