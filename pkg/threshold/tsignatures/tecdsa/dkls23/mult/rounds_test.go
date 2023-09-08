package mult_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/k256"
	"github.com/copperexchange/krypton/pkg/base/curves/p256"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	vsot_testutils "github.com/copperexchange/krypton/pkg/ot/base/vsot/testutils"
	"github.com/copperexchange/krypton/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23/mult"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23/mult/testutils"
)

func TestMultiplicationHappyPath(t *testing.T) {
	t.Parallel()
	cipherSuites := []*integration.CipherSuite{
		{
			Curve: k256.New(),
			Hash:  sha3.New256,
		},
		{
			Curve: p256.New(),
			Hash:  sha3.New256,
		},
	}
	for _, cipherSuite := range cipherSuites {
		boundedCipherSuite := cipherSuite
		t.Run(fmt.Sprintf("running multiplication happy path for curve %s", boundedCipherSuite.Curve.Name()), func(t *testing.T) {
			t.Parallel()
			sid := []byte("this is a unique session id")
			baseOtSenderOutput, baseOtReceiverOutput, err := vsot_testutils.RunVSOT(t, boundedCipherSuite.Curve, softspoken.Kappa, sid, crand.Reader)
			require.NoError(t, err)
			alice, bob, err := testutils.MakeMultParticipants(t, boundedCipherSuite, baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, sid, sid)
			require.NoError(t, err)

			a := [mult.L]curves.Scalar{}
			for i := 0; i < mult.L; i++ {
				a[i] = boundedCipherSuite.Curve.Scalar().Random(crand.Reader)
			}
			zA, zB, err := testutils.RunMult(t, alice, bob, a)
			require.NoError(t, err)
			for i := 0; i < mult.L; i++ {
				lhs := zA[i].Add(zB[i])
				rhs := a[i].Mul(bob.BTilde[i])
				require.Equal(t, 0, lhs.Cmp(rhs))
			}
		})
	}
}
