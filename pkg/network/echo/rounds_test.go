package echo_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network/echo"
)

func TestHappyPath(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha3.New256,
	}
	happyPath(t, cipherSuite, 3)
	happyPath(t, cipherSuite, 5)
}

func happyPath(t *testing.T, cipherSuite *integration.CipherSuite, n int) {
	t.Helper()
	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
	require.NoError(t, err)
	initiator, err := echo.NewInitiator(cipherSuite, identities[0].(integration.AuthKey), cohortConfig, []byte("sid"), []byte("hello world"))
	require.NoError(t, err)
	responders := make([]*echo.Participant, n-1)
	for i := 1; i < n; i++ {
		responders[i-1], err = echo.NewResponder(cipherSuite, identities[i].(integration.AuthKey), cohortConfig, []byte("sid"), initiator.MyAuthKey)
		require.NoError(t, err)
	}
	allParticipants := []*echo.Participant{initiator}
	allParticipants = append(allParticipants, responders...)
	r1OutMessages := make([]map[types.IdentityHash]*echo.Round1P2P, len(allParticipants))
	for i, participant := range allParticipants {
		var r1OutMessage map[types.IdentityHash]*echo.Round1P2P
		r1OutMessage, err := participant.Round1()
		require.NoError(t, err)
		r1OutMessages[i] = r1OutMessage
	}
	_, r2InMessages := integration_testutils.MapO2I(allParticipants, []string{}, r1OutMessages)
	r2OutMessages := make([]map[types.IdentityHash]*echo.Round2P2P, len(allParticipants))
	for i, participant := range allParticipants {
		p2p, err := participant.Round2(r2InMessages[i][initiator.MyAuthKey.Hash()])
		require.NoError(t, err)
		r2OutMessages[i] = p2p
	}
	_, r3InMessages := integration_testutils.MapO2I(allParticipants, []*echo.Round2P2P{}, r2OutMessages)
	require.NoError(t, err)

	outputMessages := make([][]byte, len(allParticipants))
	for i, participant := range allParticipants {
		nonNilR3InMessages := map[types.IdentityHash]*echo.Round2P2P{}
		for j, msg := range r3InMessages[i] {
			if msg != nil {
				nonNilR3InMessages[j] = msg
			}
		}
		outputMessages[i], err = participant.Round3(nonNilR3InMessages)
		require.NoError(t, err)
	}
	// check all output r1OutMessages are the same
	for i := range outputMessages {
		require.Equal(t, outputMessages[0], outputMessages[i])
	}
}

func TestFailIfOnlyTwoParticipants(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha3.New256,
	}
	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)
	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
	require.NoError(t, err)
	_, err = echo.NewInitiator(cipherSuite, identities[0].(integration.AuthKey), cohortConfig, []byte("sid"), []byte("hello world"))
	require.Error(t, err)
}
