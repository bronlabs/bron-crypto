package curves_testutils

import (
	"fmt"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/stretchr/testify/require"
)

type IntegerFiniteFieldInvariants[F algebra.IntegerFiniteField[F, FE], FE algebra.IntegerFiniteFieldElement[F, FE]] struct{}

func (iff *IntegerFiniteFieldInvariants[F, FE]) SetNatAndNat(t *testing.T, object algebra.NatSerialization[FE], boundedCurve curves.Curve) {
	t.Helper()

	output := object.Nat()
	object2 := output.Clone()
	object2.SetNat(object2)
	require.True(t, object2.Eq(output) == 1)

	one := object.SetNat(saferithUtils.NatOne)
	oneClone := one.AdditiveInverse().Neg()
	require.EqualValues(t, one.Bytes(), oneClone.Bytes())

	oneTimesOne := one.Mul(oneClone)
	require.True(t, oneClone.IsOne())
	require.False(t, oneClone.IsZero())
	require.True(t, oneTimesOne.IsOne() && !oneTimesOne.IsZero())
}

func (iff *IntegerFiniteFieldInvariants[F, FE]) BytesAndSetBytes(t *testing.T, object algebra.BytesSerialization[FE], boundedCurve curves.Curve) {
	// t.Helper()
	// // TODO: Line43, [LENGTH_ERROR] input length != 32 bytes
	// actual := object.Bytes()
	// require.NotZero(t, len(actual))
	// excpted, err := object.SetBytes(actual)
	// require.NoError(t, err)
	// require.Equal(t, excpted, object)

	// one, err := object.SetBytes(saferithUtils.NatOne.Bytes())
	// require.NoError(t, err)
	// oneClone := one.AdditiveInverse().Neg()
	// require.EqualValues(t, one.Bytes(), oneClone.Bytes())

	// oneTimesOne := one.Mul(oneClone)
	// require.True(t, oneClone.IsOne())
	// require.False(t, oneClone.IsZero())
	// require.True(t, oneTimesOne.IsOne() && !oneTimesOne.IsZero())
}

func (iff *IntegerFiniteFieldInvariants[F, FE]) BytesAndSetBytesSetBytesWide(t *testing.T, object algebra.BytesSerialization[FE], boundedCurve curves.Curve) {
	t.Helper()

	actual := object.Bytes()
	require.NotZero(t, len(actual))
	excpted, err := object.SetBytes(actual)
	require.NoError(t, err)
	require.Equal(t, excpted, object)

	one, err := object.SetBytesWide(saferithUtils.NatOne.Bytes())
	require.NoError(t, err)
	oneClone := one.AdditiveInverse().Neg()
	require.EqualValues(t, one.Bytes(), oneClone.Bytes())

	oneTimesOne := one.Mul(oneClone)
	require.True(t, oneClone.IsOne())
	require.False(t, oneClone.IsZero())
	require.True(t, oneTimesOne.IsOne() && !oneTimesOne.IsZero())
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
	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(fmt.Sprintf("SetNatAndNat + %s", boundedCurve.Name()), func(t *testing.T) {
			iff.SetNatAndNat(t, elementGenerator.Generate(), boundedCurve)

		})
		t.Run(fmt.Sprintf("BytesAndSetBytes + %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			iff.BytesAndSetBytes(t, elementGenerator.Generate(), boundedCurve)
		})
		t.Run(fmt.Sprintf("BytesAndSetBytesSetBytesWide + %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			iff.BytesAndSetBytesSetBytesWide(t, elementGenerator.Generate(), boundedCurve)
		})
	}

}
