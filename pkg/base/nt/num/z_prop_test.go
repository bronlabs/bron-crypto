package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"pgregory.net/rapid"
)

func IntGenerator(t *testing.T) *rapid.Generator[*num.Int] {
	return rapid.Custom(func(t *rapid.T) *num.Int {
		n := rapid.Int64().Draw(t, "n")
		return num.Z().FromInt64(n)
	})
}

func SmallIntGenerator(t *testing.T) *rapid.Generator[*num.Int] {
	return rapid.Custom(func(t *rapid.T) *num.Int {
		n := rapid.Int16().Draw(t, "n")
		return num.Z().FromInt64(int64(n))
	})
}

func TestZLikeProperties(t *testing.T) {
	t.Parallel()
	suite := properties.ZLike(t, num.Z(), IntGenerator(t))
	suite.Check(t)
}

func TestZ_FromBigRoundTrip_Property(t *testing.T) {
	t.Parallel()
	FromBigRoundTrip_Property(t, num.Z(), IntGenerator(t))
}

func TestZ_FromNatPlus_Property(t *testing.T) {
	t.Parallel()
	FromNatPlusRoundTrip_Property(t, num.Z(), NatPlusGenerator(t))
}

func TestZ_FromNat_Property(t *testing.T) {
	t.Parallel()
	FromNatRoundTrip_Property(t, num.Z(), NatGenerator(t), true)
}

func TestZ_FromRat_Property(t *testing.T) {
	t.Parallel()
	FromRatRoundTrip_Property(t, num.Z(), SmallRatGenerator(t), true, true)
}

func TestZ_HashCodeEqualityCorrespondence_Property(t *testing.T) {
	t.Parallel()
	HashCodeEqualityCorrespondence_Property(t, IntGenerator(t))
}
