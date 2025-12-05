package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"pgregory.net/rapid"
)

func NatGenerator(t *testing.T) *rapid.Generator[*num.Nat] {
	return rapid.Custom(func(t *rapid.T) *num.Nat {
		n := rapid.Uint64().Draw(t, "n")
		return num.N().FromUint64(n)
	})
}

func TestNLikeProperties(t *testing.T) {
	t.Parallel()
	suite := properties.NLike(t, num.N(), NatGenerator(t))
	suite.Check(t)
}

func TestNat_FromBigRoundTrip_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	FromBigRoundTrip_Property(t, num.N(), g)
}

func TestNat_FromNatPlus_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	FromNatPlusRoundTrip_Property(t, num.N(), g)
}
