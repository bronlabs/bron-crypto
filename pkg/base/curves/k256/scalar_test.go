package k256_test

import (
	"bytes"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

func equals[E algebra.Element[E]](lhs, rhs E) bool {
	return lhs.Equal(rhs)
}

func equalsByBytes[F algebra.UintLike[F]](lhs, rhs F) bool {
	return bytes.Equal(lhs.Nat().Bytes(), rhs.Nat().Bytes())
}

func isOne[F algebra.FieldElement[F]](f F) bool {
	return f.IsOne()
}

func TestAdd(t *testing.T) {
	t.Parallel()

	two := new(saferith.Nat).SetUint64(2)
	three := new(saferith.Nat).SetUint64(3)
	five := new(saferith.Nat).SetUint64(5)

	scs := k256.NewScalarField()

	sc2, err := scs.FromNat(two)
	require.NoError(t, err)
	sc3, err := scs.FromNat(three)
	require.NoError(t, err)
	sc5, err := scs.FromNat(five)
	require.NoError(t, err)

	require.True(t, equals(sc5, sc2.Add(sc3)))
	require.True(t, equalsByBytes(sc5, sc2.Add(sc3)))
}

func TestOther(t *testing.T) {
	t.Parallel()

	scs := k256.NewScalarField()

	one := scs.One()
	require.True(t, isOne(one))

}
