package dhc_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/ecies/ecsvdp/dhc"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{k256.New(), edwards25519.New()} {
		c := curve
		t.Run(fmt.Sprintf("running test for curve =%s", c.Name()), func(t *testing.T) {
			t.Parallel()
			alicePrivateKey := c.Scalar().Random(crand.Reader)
			alicePublicKey := c.ScalarBaseMult(alicePrivateKey)

			bobPrivateKey := c.Scalar().Random(crand.Reader)
			bobPublicKey := c.ScalarBaseMult(bobPrivateKey)

			aliceDerivation, err := dhc.DeriveSharedSecretValue(alicePrivateKey, bobPublicKey)
			require.NoError(t, err)
			require.False(t, aliceDerivation.IsZero())
			bobDerivation, err := dhc.DeriveSharedSecretValue(bobPrivateKey, alicePublicKey)
			require.NoError(t, err)
			require.False(t, bobDerivation.IsZero())

			require.Zero(t, aliceDerivation.Cmp(bobDerivation))
		})
	}
}
