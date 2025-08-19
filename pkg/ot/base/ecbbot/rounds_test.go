package ecbbot_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	ecbbottestutils "github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot/testutils"
)

func Test_HappyPathRandomOT(t *testing.T) {
	t.Parallel()
	const CHI = 128
	const L = 4
	prng := crand.Reader
	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(t, err)
	tape := hagrid.NewTranscript("test")
	curve := k256.NewCurve()

	senderOutput, receiverOutput, err := ecbbottestutils.RunBBOT(CHI, L, curve, sessionId, tape, prng)
	require.NoError(t, err)
	ecbbottestutils.ValidateOT(t, CHI, L, senderOutput, receiverOutput)
}

//func Benchmark_BBOT(b *testing.B) {
//	Xi := 128
//	L := 4
//	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
//	require.NoError(b, err)
//	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
//	require.NoError(b, err)
//	senderKey, receiverKey := authKeys[0], authKeys[1]
//	uniqueSessionId := [32]byte{}
//	_, err = crand.Read(uniqueSessionId[:])
//	require.NoError(b, err)
//	for _, curve := range curveInstances {
//		_, _, err := ecbbottestutils.RunBBOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
//		require.NoError(b, err)
//	}
//}
//
//func getKeys(t *testing.T) (senderKey, receiverKey types.AuthKey) {
//	t.Helper()
//	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
//	require.NoError(t, err)
//	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
//	require.NoError(t, err)
//	return authKeys[0], authKeys[1]
//}
