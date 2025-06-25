package dkls23_softspoken_test

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	bbot_testutils "github.com/bronlabs/bron-crypto/pkg/ot/base/bbot/testutils"
	vsot_testutils "github.com/bronlabs/bron-crypto/pkg/ot/base/vsot/testutils"
	mult "github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23_softspoken"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23_softspoken/testutils"
)

func cipherSuites(t *testing.T) []types.SigningSuite {
	t.Helper()
	cs := make([]types.SigningSuite, 2)
	var err error
	cs[0], err = ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(t, err)
	cs[1], err = ttu.MakeSigningSuite(p256.NewCurve(), sha3.New256)
	require.NoError(t, err)
	return cs
}

var baseOTrunners = []func(senderKey, receiverKey types.AuthKey, batchSize, messageLength int, curve curves.Curve, uniqueSessionId []byte, rng io.Reader) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error){
	vsot_testutils.RunVSOT,
	bbot_testutils.RunBBOT,
}

func TestMultiplicationHappyPath(t *testing.T) {
	t.Parallel()
	for _, cipherSuite := range cipherSuites(t) {
		for _, baseOTrunner := range baseOTrunners {
			boundedCipherSuite := cipherSuite
			boundedBaseOTrunner := baseOTrunner
			authKeys, err := ttu.MakeTestAuthKeys(boundedCipherSuite, 2)
			require.NoError(t, err)
			senderKey, receiverKey := authKeys[0], authKeys[1]
			t.Run(fmt.Sprintf("running multiplication happy path for curve %s", boundedCipherSuite.Curve().Name()), func(t *testing.T) {
				t.Parallel()
				sid := []byte("this is a unique session id")
				baseOtSenderOutput, baseOtReceiverOutput, err := boundedBaseOTrunner(senderKey, receiverKey, ot.Kappa, 1, boundedCipherSuite.Curve(), sid, crand.Reader)
				require.NoError(t, err)

				seededPrng, err := fkechacha20.NewPrng(nil, nil)
				require.NoError(t, err)

				alice, bob, err := testutils.MakeMult2Participants(t, boundedCipherSuite.Curve(), baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, seededPrng, sid, sid)
				require.NoError(t, err)

				a := [mult.L]curves.Scalar{}
				for i := 0; i < mult.L; i++ {
					a[i], err = boundedCipherSuite.Curve().ScalarField().Random(crand.Reader)
					require.NoError(t, err)
				}
				b, zA, zB, err := testutils.RunMult2(t, alice, bob, a)
				require.NoError(t, err)
				for i := 0; i < mult.L; i++ {
					lhs := zA[i].Add(zB[i])
					rhs := a[i].Mul(b)
					require.Equal(t, algebra.Ordering(0), lhs.Cmp(rhs))
				}
			})
		}
	}
}

// This test sets the SID for the participants to be different before running the
// protocol and checks that the multiplication fails.
func Test_MultiplicationFailForDifferentSID(t *testing.T) {
	t.Parallel()
	for _, cipherSuite := range cipherSuites(t) {
		for _, baseOTrunner := range baseOTrunners {
			boundedCipherSuite := cipherSuite
			boundedBaseOTrunner := baseOTrunner
			authKeys, err := ttu.MakeTestAuthKeys(boundedCipherSuite, 2)
			require.NoError(t, err)
			senderKey, receiverKey := authKeys[0], authKeys[1]
			t.Run(fmt.Sprintf("running multiplication happy path for curve %s", boundedCipherSuite.Curve().Name()), func(t *testing.T) {
				t.Parallel()
				sid := []byte("this is a unique session id")
				sid2 := []byte("this is a different unique session id")
				baseOtSenderOutput, baseOtReceiverOutput, err := boundedBaseOTrunner(senderKey, receiverKey, ot.Kappa, 1, boundedCipherSuite.Curve(), sid, crand.Reader)
				require.NoError(t, err)

				seededPrng, err := fkechacha20.NewPrng(nil, nil)
				require.NoError(t, err)

				alice, bob, err := testutils.MakeMult2Participants(t, boundedCipherSuite.Curve(), baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, seededPrng, sid, sid2)
				require.NoError(t, err)

				a := [mult.L]curves.Scalar{}
				for i := 0; i < mult.L; i++ {
					a[i], err = boundedCipherSuite.Curve().ScalarField().Random(crand.Reader)
					require.NoError(t, err)
				}

				_, _, _, err = testutils.RunMult2(t, alice, bob, a)
				require.Error(t, err)
			})
		}
	}
}

// This test runs the protocol twice with the same SID. The second run, Alice
// replays intermediate messages from the first run. The test checks that the
// multiplication fails. Note that a replay from Bob is not possible since Bob
// sets the input to the protocol with his first message (to protect against it
// we must use a different SID for the second run)
func Test_MultiplicationFailForReplayedMessages(t *testing.T) {
	t.Parallel()
	for _, cipherSuite := range cipherSuites(t) {
		for _, baseOTrunner := range baseOTrunners {
			boundedCipherSuite := cipherSuite
			boundedBaseOTrunner := baseOTrunner
			authKeys, err := ttu.MakeTestAuthKeys(boundedCipherSuite, 2)
			require.NoError(t, err)
			senderKey, receiverKey := authKeys[0], authKeys[1]
			t.Run(fmt.Sprintf("running multiplication happy path for curve %s", boundedCipherSuite.Curve().Name()), func(t *testing.T) {
				t.Parallel()
				sid := []byte("this is a unique session id")
				baseOtSenderOutput, baseOtReceiverOutput, err := boundedBaseOTrunner(senderKey, receiverKey, ot.Kappa, 1, boundedCipherSuite.Curve(), sid, crand.Reader)
				require.NoError(t, err)

				seededPrng, err := fkechacha20.NewPrng(nil, nil)
				require.NoError(t, err)

				alice, bob, err := testutils.MakeMult2Participants(t, boundedCipherSuite.Curve(), baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, seededPrng, sid, sid)
				require.NoError(t, err)

				a := [mult.L]curves.Scalar{}
				for i := 0; i < mult.L; i++ {
					a[i], err = boundedCipherSuite.Curve().ScalarField().Random(crand.Reader)
					require.NoError(t, err)
				}

				// First run
				b, bobOutput_Run1, err := bob.Round1()
				require.NoError(t, err)
				zA, aliceOutput_Run1, err := alice.Round2(bobOutput_Run1, a)
				require.NoError(t, err)
				zB, err := bob.Round3(aliceOutput_Run1)
				require.NoError(t, err)

				// Check that the first multiplication is correct.
				for i := 0; i < mult.L; i++ {
					lhs := zA[i].Add(zB[i])
					rhs := a[i].Mul(b)
					require.Equal(t, algebra.Ordering(0), lhs.Cmp(rhs))
				}

				// Second Run. Alice replays the messages from the first run.
				alice, bob, err = testutils.MakeMult2Participants(t, boundedCipherSuite.Curve(), baseOtReceiverOutput, baseOtSenderOutput, crand.Reader, crand.Reader, seededPrng, sid, sid)
				require.NoError(t, err)

				_, bobOutput_Run2, err := bob.Round1()
				require.NoError(t, err)
				_, _, err = alice.Round2(bobOutput_Run2, a)
				require.NoError(t, err)
				_, err = bob.Round3(aliceOutput_Run1)
				require.Error(t, err)
			})
		}
	}
}
