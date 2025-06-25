package ecbbot_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	ecbbottestutils "github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot/testutils"
)

var curveInstances = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
}

func Test_HappyPathBBOT_ROT(t *testing.T) {
	t.Parallel()
	Xi := 128
	L := 4
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		senderOutput, receiverOutput, err := ecbbottestutils.RunBBOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		ecbbottestutils.ValidateOT(t, Xi, L, senderOutput, receiverOutput)
	}
}

func Benchmark_BBOT(b *testing.B) {
	Xi := 128
	L := 4
	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(b, err)
	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
	require.NoError(b, err)
	senderKey, receiverKey := authKeys[0], authKeys[1]
	uniqueSessionId := [32]byte{}
	_, err = crand.Read(uniqueSessionId[:])
	require.NoError(b, err)
	for _, curve := range curveInstances {
		_, _, err := ecbbottestutils.RunBBOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(b, err)
	}
}

func getKeys(t *testing.T) (senderKey, receiverKey types.AuthKey) {
	t.Helper()
	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(t, err)
	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
	require.NoError(t, err)
	return authKeys[0], authKeys[1]
}
