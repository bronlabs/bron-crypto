package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/cronokirby/saferith"

	// fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"

	"github.com/stretchr/testify/require"
)

type NatSerializationInvariants[E algebra.Object] struct{}

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
	// TODO
}

func (nsi *NatSerializationInvariants[E]) Nat(t *testing.T, nat algebra.NatSerialization[E]) {
	t.Helper()
	// TODO
	require.IsType(t, &saferith.Nat{}, nat.Nat())
}
