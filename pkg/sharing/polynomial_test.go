package sharing

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
)

func TestNewPoly(t *testing.T) {
	curve := curves.BLS12381G1()
	secret := curve.NewScalar().Hash([]byte("test"))

	poly := new(Polynomial).NewPolynomial(secret, 4, crand.Reader)
	require.NotNil(t, poly)

	require.Equal(t, poly.Coefficients[0], secret)
}
