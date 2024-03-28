package echo_test

import (
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	t "github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network/echo"
	echotu "github.com/copperexchange/krypton-primitives/pkg/network/echo/testutils"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()
	for _, c := range []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve()} {
		for _, nn := range []int{3, 5, 10} {
			for _, m := range []string{"Proof of Work > Proof of State", "Dolev-Strong doesn't work for t>=n/2 if nodes are passive"} {
				for hi, hh := range []func() hash.Hash{sha3.New256, sha512.New512_256} {
					msg := m
					curve := c
					n := nn
					h := hh
					t.Run(fmt.Sprintf("%s-%d-hi=%d-msg: %s", curve.Name(), n, hi, msg), func(t *testing.T) {
						cipherSuite, err := ttu.MakeSigningSuite(curve, h)
						require.NoError(t, err)
						happyPath(t, cipherSuite, nn, msg)
					})
				}
			}
		}
	}
}

func happyPath(t *testing.T, cipherSuite t.SigningSuite, n int, msg string) {
	t.Parallel()
	sid := []byte("sid")
	// Scenario setup
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	// Protocol setup
	protocol, err := ttu.NewProtocol(cipherSuite.Curve(), identities...)
	require.NoError(t, err)
	participants, err := echotu.MakeEchoParticipants([]byte(msg), protocol, testutils.TestRng(), sid)
	require.NoError(t, err)
	// Run protocol
	outputMessages, err := echotu.RunEcho(participants)
	// check all output messages are the same
	echotu.ValidateEcho(t, outputMessages)
}

func TestFailIfOnlyTwoParticipants(t *testing.T) {
	n := 2
	curve := k256.NewCurve()
	signingSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(t, err)
	authKeys, err := ttu.MakeTestAuthKeys(signingSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.NewProtocol(curve, authKeys...)
	require.NoError(t, err)
	baseParticipants, err := ttu.MakeParticipants(protocol, testutils.TestRng(), []byte("sid"))
	require.NoError(t, err)
	_, err = echo.NewInitiator(baseParticipants[0], []byte("hello world"))
	require.Error(t, err)
	require.True(t, errs.HasSize(err))
}
