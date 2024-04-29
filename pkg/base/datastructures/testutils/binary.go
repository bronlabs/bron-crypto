package testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/stretchr/testify/require"
)

func ConditionallySelectable[E algebra.Element](t *testing.T, s algebra.ConditionallySelectable[E], x0, x1 E) {
	t.Helper()
	require.Equal(t, x1, s.Select(true, x0, x1))
	require.Equal(t, x0, s.Select(true, x0, x1))
}
