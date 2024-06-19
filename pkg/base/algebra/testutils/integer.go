package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/stretchr/testify/require"
)

type IntegerFiniteFieldInvariants[F algebra.IntegerFiniteField[F, FE], FE algebra.IntegerFiniteFieldElement[F, FE]] struct{}

func (iff *IntegerFiniteFieldInvariants[F, FE]) SetNatAndNat(t *testing.T, object algebra.NatSerialization[FE]) {
	t.Helper()

	output := object.Nat()
	object2 := output.Clone()
	object2.SetNat(object2)
	require.True(t, object2.Eq(output) == 1)

	one := object.SetNat(saferithUtils.NatOne)
	oneClone := one.AdditiveInverse().Neg()
	require.EqualValues(t, one.Bytes(), oneClone.Bytes())

	require.True(t, oneClone.Equal(one))
	require.False(t, oneClone.IsZero())
}

func (iff *IntegerFiniteFieldInvariants[F, FE]) BytesAndSetBytes(t *testing.T, object algebra.BytesSerialization[FE]) {
	t.Helper()

	actual := object.Bytes()
	require.NotZero(t, len(actual))
	excpted, err := object.SetBytes(actual)
	require.NoError(t, err)
	require.Equal(t, excpted, object)

	one32Bytes := bitstring.PadToLeft(saferithUtils.NatOne.Bytes(), len(object.Bytes())-1)
	one, err := object.SetBytes(one32Bytes)
	require.NoError(t, err)
	oneClone := one.AdditiveInverse().Neg()
	require.EqualValues(t, one.Bytes(), oneClone.Bytes())

	require.True(t, oneClone.Equal(one))
	require.False(t, oneClone.IsZero())
}

func (iff *IntegerFiniteFieldInvariants[F, FE]) BytesAndSetBytesWide(t *testing.T, object algebra.BytesSerialization[FE]) {
	t.Helper()

	actual := object.Bytes()
	require.NotZero(t, len(actual))
	excpted, err := object.SetBytes(actual)
	require.NoError(t, err)
	require.Equal(t, excpted, object)

	one32Bytes := bitstring.PadToLeft(saferithUtils.NatOne.Bytes(), len(object.Bytes())-1)
	one, err := object.SetBytes(one32Bytes)
	require.NoError(t, err)
	oneClone := one.AdditiveInverse().Neg()
	require.EqualValues(t, one.Bytes(), oneClone.Bytes())

	require.True(t, oneClone.Equal(one))
	require.False(t, oneClone.IsZero())
}

func CheckIntegerFiniteFieldInvariants[F algebra.IntegerFiniteField[F, FE], FE algebra.IntegerFiniteFieldElement[F, FE]](t *testing.T, f F, elementGenerator fu.ObjectGenerator[FE]) {
	t.Helper()
	require.NotNil(t, f)
	require.NotNil(t, elementGenerator)
	// CheckIntegerRingInvariants[F, FE](t, f, elementGenerator) //TODO
	// CheckEuclideanDomainInvariants[F, FE](t, f, elementGenerator) //TODO
	CheckNatSerializationInvariants[FE](t, elementGenerator)
	CheckBytesSerializationInvariants[FE](t, elementGenerator)
	CheckFiniteFieldInvariants[F, FE](t, f, elementGenerator)

	iff := &IntegerFiniteFieldInvariants[F, FE]{}
	t.Run("SetNatAndNat", func(t *testing.T) {
		iff.SetNatAndNat(t, elementGenerator.Generate())
	})
	t.Run("BytesAndSetBytes", func(t *testing.T) {
		iff.BytesAndSetBytes(t, elementGenerator.Generate())
	})
	t.Run("BytesAndSetBytesWide", func(t *testing.T) {
		iff.BytesAndSetBytesWide(t, elementGenerator.Generate())
	})
}
