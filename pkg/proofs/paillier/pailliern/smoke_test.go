package pailliern_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/pailliern"
)

func TestSmoke(t *testing.T) {
	t.Parallel()

	kappa := int(pailliern.M * math.Log2(pailliern.Alpha)) // κ ≥ m log(ɑ)

	require.GreaterOrEqual(t, kappa, base.ComputationalSecurity,
		"Ensure a minimum of 128-bit computational security")
}
