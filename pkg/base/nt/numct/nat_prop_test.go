package numct_test

import (
	"testing"

	aprop "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"pgregory.net/rapid"
)

func NatGenerator() *rapid.Generator[*numct.Nat] {
	return rapid.Custom(func(t *rapid.T) *numct.Nat {
		n := rapid.Uint64().Draw(t, "n")
		return numct.NewNat(n)
	})
}

func NonZeroNatGenerator() *rapid.Generator[*numct.Nat] {
	return rapid.Custom(func(t *rapid.T) *numct.Nat {
		n := rapid.Uint64Min(1).Draw(t, "n")
		return numct.NewNat(n)
	})
}

func TestMonoidalProperties(t *testing.T) {
	t.Parallel()
	suite := aprop.NewLowLevelMonoidalPropertySuite(t, NatGenerator(), NonZeroNatGenerator(), true)
	suite.CheckAll(t)
}
