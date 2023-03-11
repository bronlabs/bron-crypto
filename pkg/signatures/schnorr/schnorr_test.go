package schnorr_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
	"github.com/stretchr/testify/require"
)

func Test_happyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{
		curves.K256(), curves.P256(), curves.ED25519(),
	} {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name), func(tt *testing.T) {
			tt.Parallel()
			message := []byte("something")
			privateKey := schnorr.Keygen(boundedCurve, nil, crand.Reader)
			require.NotNil(tt, privateKey)
			signature, err := privateKey.Sign(crand.Reader, message, nil)
			require.NoError(tt, err)
			require.NotNil(tt, signature)
			err = schnorr.Verify(&privateKey.PublicKey, message, signature, nil)
			require.NoError(tt, err)
		})
	}
}
