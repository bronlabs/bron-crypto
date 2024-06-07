package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type NatSerializationInvariants[E algebra.Element] struct{}

type BytesSerializationInvariants[E algebra.BytesSerialization[E]] struct{}

func (nsi *NatSerializationInvariants[E]) Uint64(t *testing.T, object algebra.NatSerialization[E], input E) {
	t.Helper()
	require.NotPanics(t, func() {
		object.Uint64()
	})
	actual := object.Uint64()
	require.IsType(t, uint64(0), actual)
	require.GreaterOrEqual(t, actual, uint64(0))
}

func (nsi *NatSerializationInvariants[E]) SetNatAndNat(t *testing.T, object algebra.NatSerialization[E]) {
	t.Helper()
	output := object.Nat()
	object2 := output.Clone()
	object2.SetNat(object2)
	require.True(t, object2.Eq(output) == 1)
}

func (bsi *BytesSerializationInvariants[E]) BytesAndSetBytes(t *testing.T, object algebra.BytesSerialization[E]) {
	t.Helper()

	actual := object.Bytes()
	require.NotZero(t, len(actual))
	excpted, err := object.SetBytes(actual)
	require.NoError(t, err)
	require.Equal(t, excpted, object)
}
func CheckNatSerializationInvariants[E algebra.NatSerialization[E]](t *testing.T, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()

	nsi := &NatSerializationInvariants[E]{}
	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero

	t.Run("SetNatAndNat", func(t *testing.T) {
		t.Parallel()
		nsi.SetNatAndNat(t, gen.Generate())
	})
}
func CheckBytesSerializationInvariants[E algebra.BytesSerialization[E]](t *testing.T, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()

	bsi := &BytesSerializationInvariants[E]{}
	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero

	t.Run("BytesAndSetBytes", func(t *testing.T) {
		t.Parallel()
		bsi.BytesAndSetBytes(t, gen.Generate())
	})
}
