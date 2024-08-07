package base_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
)

func TestSmoke(t *testing.T) {
	t.Parallel()
	require.GreaterOrEqual(t, base.ComputationalSecurity, 128,
		"Ensure a minimum of 128-bit computational security")
	require.GreaterOrEqual(t, base.StatisticalSecurity, 80,
		"Ensure a minimum of 80-bit statistical security")
	require.GreaterOrEqual(t, base.CollisionResistance, 2*base.ComputationalSecurity,
		"Ensure a minimum of 128-bit computational security (birthday paradox)")
	require.Equal(t, base.CollisionResistanceBytes*8, base.CollisionResistance,
		"Ensure CollisionResistanceBytes matches CollisionResistance")
	require.Equal(t, 1<<base.ComputationalSecurityLog2, base.ComputationalSecurity,
		"Ensure ComputationalSecurityLog2 matches ComputationalSecurity")
	require.GreaterOrEqual(t, base.RandomOracleHashFunction().Size(), base.CollisionResistanceBytes,
		"hash function output length is too short")
}
