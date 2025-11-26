package numct_test

import (
	"testing"

	aprop "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
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
	suite := aprop.NewLowLevelGroupalPropertySuite(t, IntGenerator(), IntGeneratorNonZero(), true)
	suite.CheckAll(t)
}
