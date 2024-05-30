package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

type NatSerializationInvariants[E algebra.Element] struct{}

type BytesSerializationInvariants[E algebra.Element] struct{}

func (nsi *NatSerializationInvariants[E]) Uint64(t *testing.T, nat algebra.NatSerialization[E], input E) {
	t.Helper()
	require.NotPanics(t, func() {
		nat.Uint64()
	})
	actual := nat.Uint64()
	require.IsType(t, uint64(0), actual)
	require.GreaterOrEqual(t, actual, uint64(0))
}

func (nsi *NatSerializationInvariants[E]) SetNat(t *testing.T, nat algebra.NatSerialization[E], v *saferith.Nat) {
	t.Helper()
	// val1 := nat.SetNat(v)
	// TODO
}

func (nsi *NatSerializationInvariants[E]) Nat(t *testing.T, nat algebra.NatSerialization[E]) {
	t.Helper()
	// TODO
	require.IsType(t, &saferith.Nat{}, nat.Nat())
}

func (bsi *BytesSerializationInvariants[E]) Bytes(t *testing.T, element algebra.BytesSerialization[E]) {
	t.Helper()

	actual := element.Bytes()
	require.Len(t, actual, 32)
	excpted, err := element.SetBytes(actual)
	require.NoError(t, err)
	require.Equal(t, excpted, element)
}
func (bsi *BytesSerializationInvariants[E]) SetBytes(t *testing.T, element algebra.BytesSerialization[E]) {
	t.Helper()

	actual := element.Bytes()
	require.Len(t, actual, 32)
	excpted, err := element.SetBytes(actual)
	require.NoError(t, err)
	require.Equal(t, excpted, element)
}
func CheckBytesSerializationInvariants[E algebra.Element](t *testing.T, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()

}
