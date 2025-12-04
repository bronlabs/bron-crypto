package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties4"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestNPlusLikeProperties4(t *testing.T) {
	t.Parallel()
	properties4.NPlusLikeModel(t, num.NPlus(), NatPlusGenerator(t)).Check(t)
}

func TestNLikeProperties4(t *testing.T) {
	t.Parallel()
	properties4.NLikeModel(t, num.N(), NatGenerator(t)).Check(t)
}

// TestNPlusLikeProperties4_Fluent demonstrates the fluent API.
func TestNPlusLikeProperties4_Fluent(t *testing.T) {
	t.Parallel()

	properties4.New(t, num.NPlus(), NatPlusGenerator(t)).
		WithAddition(properties4.AdditionOp(
			func(a, b *num.NatPlus) *num.NatPlus { return a.Add(b) },
			nil, // No zero in N+
			nil, // No negation in N+
		)).
		WithMultiplication(properties4.MultiplicationOp(
			func(a, b *num.NatPlus) *num.NatPlus { return a.Mul(b) },
			num.NPlus().One,
			nil,
			true,
		)).
		WithTheory(properties4.NPlusLikeTheory[*num.PositiveNaturalNumbers, *num.NatPlus]()).
		CheckAll(t)
}

// TestNPlus_TrySub_Property4 demonstrates using the suite's context for custom tests.
func TestNPlus_TrySub_Property4(t *testing.T) {
	t.Parallel()

	suite := properties4.New(t, num.NPlus(), NatPlusGenerator(t))

	rapid.Check(t, func(rt *rapid.T) {
		a := suite.Context().Draw(rt, "a")
		b := suite.Context().Draw(rt, "b")

		diff, err := a.TrySub(b)
		if a.IsLessThanOrEqual(b) {
			require.ErrorIs(t, err, num.ErrOutOfRange)
		} else {
			require.NoError(t, err)
			require.True(t, diff.Add(b).Equal(a))
		}
	})
}

// TestNPlusLikeProperties4_CustomProperty demonstrates adding custom properties.
func TestNPlusLikeProperties4_CustomProperty(t *testing.T) {
	t.Parallel()

	// Create a custom property for testing
	mulIdentityCustom := properties4.Property[*num.PositiveNaturalNumbers, *num.NatPlus]{
		Name: "Custom_MulIdentity",
		Check: func(t *testing.T, ctx *properties4.Context[*num.PositiveNaturalNumbers, *num.NatPlus]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				one := ctx.Carrier().One()
				result := a.Mul(one)
				require.True(t, result.Equal(a), "a * 1 should equal a")
			})
		},
	}

	properties4.NPlusLikeModel(t, num.NPlus(), NatPlusGenerator(t)).
		With(mulIdentityCustom).
		Check(t)
}
