package replicated_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
)

func Test_ExpTable(t *testing.T) {
	t.Parallel()
	expTable, err := replicated.BuildExpTable(2, 3)
	require.NoError(t, err)
	require.NotNil(t, expTable)
}

func Test_MulTable(t *testing.T) {
	t.Parallel()
	mulTable, err := replicated.BuildMulTable(2, 8)
	require.NoError(t, err)
	require.NotNil(t, mulTable)
}
