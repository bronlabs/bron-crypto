package k256_test

import (
	"testing"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves2/k256"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

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

	require.True(t, sc5.Equal(sc2.Add(sc3)))
	require.Equal(t, sc5.Nat().Bytes(), sc2.Add(sc3).Nat().Bytes())
}

func TestOther(t *testing.T) {
	t.Parallel()

	scs := k256.NewScalarField()

	one := scs.One()
	require.True(t, one.IsOne())

}
