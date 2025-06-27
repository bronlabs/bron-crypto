package k256_test

import (
	"bytes"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/stretchr/testify/require"
)

func equals[E algebra.Element[E]](lhs, rhs E) bool {
	return lhs.Equal(rhs)
}

func equalsByBytes[F algebra.UintLike[F]](lhs, rhs F) bool {
	return bytes.Equal(lhs.Bytes(), rhs.Bytes())
}

func isOne[F algebra.FieldElement[F]](f F) bool {
	return f.IsOne()
}

func TestAdd(t *testing.T) {
	t.Parallel()

	two := cardinal.New(2)
	three := cardinal.New(3)
	five := cardinal.New(5)

	scs := k256.NewScalarField()

	sc2, err := scs.FromCardinal(two)
	require.NoError(t, err)
	sc3, err := scs.FromCardinal(three)
	require.NoError(t, err)
	sc5, err := scs.FromCardinal(five)
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
