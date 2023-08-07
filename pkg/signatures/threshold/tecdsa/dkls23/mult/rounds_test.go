package mult_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	vsot_test_utils "github.com/copperexchange/knox-primitives/pkg/ot/base/vsot/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/mult"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/mult/test_utils"
)

func TestMultiplicationHappyPath(t *testing.T) {
	t.Parallel()
	cipherSuites := []*integration.CipherSuite{
		{
			Curve: curves.K256(),
			Hash:  sha3.New256,
		},
		{
			Curve: curves.P256(),
			Hash:  sha3.New256,
		},
	}
	for _, cipherSuite := range cipherSuites {
		boundedCipherSuite := cipherSuite
		t.Run(fmt.Sprintf("running multiplication happy path for curve %s", boundedCipherSuite.Curve.Name), func(t *testing.T) {
			t.Parallel()
			sid := []byte("this is a unique session id")
			baseOtSenderOutput, baseOtReceiverOutput, err := vsot_test_utils.RunVSOT(t, boundedCipherSuite.Curve, softspoken.Kappa, sid)
			require.NoError(t, err)
			alice, bob, err := test_utils.MakeMultParticipants(t, boundedCipherSuite, baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, sid, sid)
			require.NoError(t, err)

			a := [mult.L]curves.Scalar{}
			for i := 0; i < mult.L; i++ {
				a[i] = boundedCipherSuite.Curve.Scalar.Random(crand.Reader)
			}
			zA, zB, err := test_utils.RunMult(t, alice, bob, a)
			require.NoError(t, err)
			for i := 0; i < mult.L; i++ {
				lhs := zA[i].Add(zB[i])
				rhs := a[i].Mul(bob.BTilde[i])
				require.Equal(t, 0, lhs.Cmp(rhs))
			}
		})
	}
}
