package numct_test

import (
	"testing"

	aprop "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func IntGenerator() *rapid.Generator[*numct.Int] {
	return rapid.Custom(func(t *rapid.T) *numct.Int {
		n := rapid.Int64().Draw(t, "n")
		return numct.NewInt(n)
	})
}

func IntGeneratorNonZero() *rapid.Generator[*numct.Int] {
	return rapid.Custom(func(t *rapid.T) *numct.Int {
		n := rapid.Int64().Filter(func(x int64) bool { return x != 0 }).Draw(t, "n")
		return numct.NewInt(n)
	})
}

func IntGeneratorPositive() *rapid.Generator[*numct.Int] {
	return rapid.Custom(func(t *rapid.T) *numct.Int {
		n := rapid.Int64Min(1).Draw(t, "n")
		return numct.NewInt(n)
	})
}

func IntGeneratorNegative() *rapid.Generator[*numct.Int] {
	return rapid.Custom(func(t *rapid.T) *numct.Int {
		n := rapid.Int64Max(-1).Draw(t, "n")
		return numct.NewInt(n)
	})
}

func TestGroupalProperties(t *testing.T) {
	t.Parallel()
	suite := aprop.NewLowLevelGroupalPropertySuite(t, IntGenerator(), true)
	suite.CheckAll(t)
}

func TestSetOne_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := IntGenerator().Draw(t, "x")
		var one, actual numct.Int
		one.SetOne()
		actual.Mul(x, &one)
		require.Equal(t, ct.True, actual.Equal(x))
	})
}

func TestMul_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := IntGenerator().Draw(t, "x")
		y := IntGenerator().Draw(t, "y")

		var actual numct.Int
		actual.Mul(y, x)
		expected := (*numct.Int)(new(saferith.Int).Mul((*saferith.Int)(x), (*saferith.Int)(y), -1))

		require.Equal(t, ct.True, actual.Equal(expected))
	})
}
