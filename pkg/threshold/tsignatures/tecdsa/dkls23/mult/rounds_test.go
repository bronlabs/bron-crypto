package mult_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	vsot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/mult"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/mult/testutils"
)

var cipherSuites = []*integration.CipherSuite{
	{
		Curve: k256.New(),
		Hash:  sha3.New256,
	},
	{
		Curve: p256.New(),
		Hash:  sha3.New256,
	},
}

func TestMultiplicationHappyPath(t *testing.T) {
	t.Parallel()
	for _, cipherSuite := range cipherSuites {
		boundedCipherSuite := cipherSuite
		t.Run(fmt.Sprintf("running multiplication happy path for curve %s", boundedCipherSuite.Curve.Name()), func(t *testing.T) {
			t.Parallel()
			sid := []byte("this is a unique session id")
			baseOtSenderOutput, baseOtReceiverOutput, err := vsot_testutils.RunVSOT(t, boundedCipherSuite.Curve, softspoken.Kappa, sid, crand.Reader)
			require.NoError(t, err)

			seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
			require.NoError(t, err)

			alice, bob, err := testutils.MakeMultParticipants(t, boundedCipherSuite, baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, seededPrng, sid, sid)
			require.NoError(t, err)

			a := [mult.L]curves.Scalar{}
			for i := 0; i < mult.L; i++ {
				a[i], err = boundedCipherSuite.Curve.Scalar().Random(crand.Reader)
				require.NoError(t, err)
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

// This test sets the SID for the participants to be different before running the
// protocol and checks that the multiplication fails.
func Test_MultiplicationFailForDifferentSID(t *testing.T) {
	t.Parallel()
	for _, cipherSuite := range cipherSuites {
		boundedCipherSuite := cipherSuite
		t.Run(fmt.Sprintf("running multiplication happy path for curve %s", boundedCipherSuite.Curve.Name()), func(t *testing.T) {
			t.Parallel()
			sid := []byte("this is a unique session id")
			sid2 := []byte("this is a different unique session id")
			baseOtSenderOutput, baseOtReceiverOutput, err := vsot_testutils.RunVSOT(t, boundedCipherSuite.Curve, softspoken.Kappa, sid, crand.Reader)
			require.NoError(t, err)

			seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
			require.NoError(t, err)

			alice, bob, err := testutils.MakeMultParticipants(t, boundedCipherSuite, baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, seededPrng, sid, sid2)
			require.NoError(t, err)

			a := [mult.L]curves.Scalar{}
			for i := 0; i < mult.L; i++ {
				a[i], err = boundedCipherSuite.Curve.Scalar().Random(crand.Reader)
				require.NoError(t, err)
			}

			_, _, err = testutils.RunMult(t, alice, bob, a)
			require.Error(t, err)
		})
	}
}

// This test runs the protocol twice with the same SID. The second run, Alice
// replays intermediate messages from the first run. The test checks that the
// multiplication fails. Note that a replay from Bob is not possible since Bob
// sets the input to the protocol with his first message (to protect against it
// we must use a different SID for the second run)
func Test_MultiplicationFailForReplayedMessages(t *testing.T) {
	t.Parallel()
	for _, cipherSuite := range cipherSuites {
		boundedCipherSuite := cipherSuite
		t.Run(fmt.Sprintf("running multiplication happy path for curve %s", boundedCipherSuite.Curve.Name()), func(t *testing.T) {
			t.Parallel()
			sid := []byte("this is a unique session id")
			baseOtSenderOutput, baseOtReceiverOutput, err := vsot_testutils.RunVSOT(t, boundedCipherSuite.Curve, softspoken.Kappa, sid, crand.Reader)
			require.NoError(t, err)

			seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
			require.NoError(t, err)

			alice, bob, err := testutils.MakeMultParticipants(t, boundedCipherSuite, baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, seededPrng, sid, sid)
			require.NoError(t, err)

			a := [mult.L]curves.Scalar{}
			for i := 0; i < mult.L; i++ {
				a[i], err = boundedCipherSuite.Curve.Scalar().Random(crand.Reader)
				require.NoError(t, err)
			}

			// First run
			bobOutput_Run1, err := bob.Round1()
			require.NoError(t, err)
			zA, aliceOutput_Run1, err := alice.Round2(bobOutput_Run1, a)
			require.NoError(t, err)
			zB, err := bob.Round3(aliceOutput_Run1)
			require.NoError(t, err)

			// Check that the first multiplication is correct.
			for i := 0; i < mult.L; i++ {
				lhs := zA[i].Add(zB[i])
				rhs := a[i].Mul(bob.BTilde[i])
				require.Equal(t, 0, lhs.Cmp(rhs))
			}

			// Second Run. Alice replays the messages from the first run.
			alice, bob, err = testutils.MakeMultParticipants(t, boundedCipherSuite, baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, seededPrng, sid, sid)
			require.NoError(t, err)

			bobOutput_Run2, err := bob.Round1()
			require.NoError(t, err)
			_, _, err = alice.Round2(bobOutput_Run2, a)
			require.NoError(t, err)
			_, err = bob.Round3(aliceOutput_Run1)
			require.Error(t, err)
		})
	}
}
