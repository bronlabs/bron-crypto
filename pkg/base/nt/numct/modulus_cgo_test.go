//go:build !purego && !nobignum

package numct_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// Helper to create both Modulus and ModulusBasic from a uint64.
func newModulusPair(t *testing.T, v uint64) modulusPair {
	t.Helper()
	n := numct.NewNat(v)
	m, ok := numct.NewModulus(n)
	require.Equal(t, ct.True, ok)
	return modulusPair{full: m, basic: m.ModulusBasic}
}

// Helper to create both Modulus and ModulusBasic from a big.Int.
func newModulusPairFromBig(t *testing.T, v *big.Int) modulusPair {
	t.Helper()
	n := numct.NewNatFromBig(v, v.BitLen())
	m, ok := numct.NewModulus(n)
	require.Equal(t, ct.True, ok)
	return modulusPair{full: m, basic: m.ModulusBasic}
}
