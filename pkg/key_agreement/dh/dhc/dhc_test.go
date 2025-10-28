package dhc_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()
	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		tester(t, k256.NewCurve())
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		tester(t, edwards25519.NewPrimeSubGroup())
	})
}

func tester[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, c curves.Curve[P, B, S]) {
	tb.Helper()
	alicePrivateKeyValue, err := c.ScalarField().Random(crand.Reader)
	require.NoError(tb, err)
	alicePublicKeyValue := c.ScalarBaseMul(alicePrivateKeyValue)

	alicePrivateKey, err := dhc.NewPrivateKey(alicePrivateKeyValue)
	require.NoError(tb, err)
	alicePublicKey, err := dhc.NewPublicKey(alicePublicKeyValue)
	require.NoError(tb, err)

	bobPrivateKeyValue, err := c.ScalarField().Random(crand.Reader)
	require.NoError(tb, err)
	bobPublicKeyValue := c.ScalarBaseMul(bobPrivateKeyValue)

	bobPrivateKey, err := dhc.NewPrivateKey(bobPrivateKeyValue)
	require.NoError(tb, err)
	bobPublicKey, err := dhc.NewPublicKey(bobPublicKeyValue)
	require.NoError(tb, err)

	aliceDerivation, err := dhc.DeriveSharedSecret(alicePrivateKey, bobPublicKey)
	require.NoError(tb, err)
	require.NotNil(tb, aliceDerivation)
	require.False(tb, ct.SliceIsZero(aliceDerivation.Bytes()) == ct.True)
	bobDerivation, err := dhc.DeriveSharedSecret(bobPrivateKey, alicePublicKey)
	require.NoError(tb, err)
	require.False(tb, ct.SliceIsZero(bobDerivation.Bytes()) == ct.True)

	require.EqualValues(tb, aliceDerivation.Bytes(), bobDerivation.Bytes())

}
