package sharing

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	"github.com/stretchr/testify/require"
)

func TestNewPoly(t *testing.T) {
	curve := bls12381.NewG1()
	secret := curve.Scalar().Hash([]byte("test"))

	poly := new(Polynomial).NewPolynomial(secret, 4, crand.Reader)
	require.NotNil(t, poly)

	require.Equal(t, poly.Coefficients[0], secret)
}
