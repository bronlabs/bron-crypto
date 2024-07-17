package echo_test

import (
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased/simulator"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/network/echo"
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
						t.Parallel()
						cipherSuite, err := ttu.MakeSigningSuite(curve, h)
						require.NoError(t, err)
						happyPath(t, cipherSuite, nn, msg)
						happyPathWithRunner(t, cipherSuite, nn, msg)
					})
				}
			}
		}
	}
}

func happyPath(t *testing.T, cipherSuite types.SigningSuite, n int, msg string) {
	t.Helper()
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeProtocol(cipherSuite.Curve(), identities)
	require.NoError(t, err)
	sid := []byte("sid")
	initiator, err := echo.NewInitiator(sid, identities[0].(types.AuthKey), protocol, []byte(msg))
	require.NoError(t, err)
	responders := make([]*echo.Participant, n-1)
	for i := 1; i < n; i++ {
		responders[i-1], err = echo.NewResponder(sid, identities[i].(types.AuthKey), protocol, initiator.IdentityKey())
		require.NoError(t, err)
	}
	allParticipants := []*echo.Participant{initiator}
	allParticipants = append(allParticipants, responders...)
	r1OutMessages := make([]network.RoundMessages[types.Protocol, *echo.Round1P2P], len(allParticipants))
	for i, participant := range allParticipants {
		r1OutMessage, err := participant.Round1()
		require.NoError(t, err)
		r1OutMessages[i] = r1OutMessage
	}
	r2InMessages := ttu.MapUnicastO2I(allParticipants, r1OutMessages)
	r2OutMessages := make([]network.RoundMessages[types.Protocol, *echo.Round2P2P], len(allParticipants))
	for i, participant := range allParticipants {
		var msg *echo.Round1P2P
		var exists bool
		if !participant.IdentityKey().Equal(initiator.IdentityKey()) {
			msg, exists = r2InMessages[i].Get(initiator.IdentityKey())
			require.True(t, exists)
		}
		p2p, err := participant.Round2(msg)
		require.NoError(t, err)
		r2OutMessages[i] = p2p
	}
	_, r3InMessages := ttu.MapO2I(allParticipants, []*echo.Round2P2P{}, r2OutMessages)
	require.NoError(t, err)

	outputMessages := make([][]byte, len(allParticipants))
	for i, participant := range allParticipants {
		nonNilR3InMessages := network.NewRoundMessages[types.Protocol, *echo.Round2P2P]()
		for iterator := r3InMessages[i].Iterator(); iterator.HasNext(); {
			mj := iterator.Next()
			if mj.Value != nil {
				nonNilR3InMessages.Put(mj.Key, mj.Value)
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

func happyPathWithRunner(t *testing.T, cipherSuite types.SigningSuite, n int, msg string) {
	t.Helper()
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeProtocol(cipherSuite.Curve(), identities)
	require.NoError(t, err)
	sid := []byte("sid")
	initiator, err := echo.NewInitiator(sid, identities[0].(types.AuthKey), protocol, []byte(msg))
	require.NoError(t, err)
	responders := make([]*echo.Participant, n-1)
	for i := 1; i < n; i++ {
		responders[i-1], err = echo.NewResponder(sid, identities[i].(types.AuthKey), protocol, initiator.IdentityKey())
		require.NoError(t, err)
	}
	allParticipants := []*echo.Participant{initiator}
	allParticipants = append(allParticipants, responders...)

	router := simulator.NewEchoBroadcastMessageRouter(protocol.Participants())
	outputMessages := make([][]byte, n)
	errChan := make(chan error)

	go func() {
		var errGrp errgroup.Group
		for i, party := range allParticipants {
			errGrp.Go(func() error {
				var err error
				outputMessages[i], err = party.Run(router)
				return err
			})
		}
		errChan <- errGrp.Wait()
	}()

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		require.Fail(t, "timeout")
	}
	for i := range allParticipants {
		require.Equal(t, outputMessages[0], outputMessages[i])
	}
}

func TestFailIfOnlyTwoParticipants(t *testing.T) {
	ct, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(t, err)
	identities, err := ttu.MakeTestIdentities(ct, 2)
	require.NoError(t, err)
	protocol, err := ttu.MakeProtocol(ct.Curve(), identities)
	require.NoError(t, err)
	_, err = echo.NewInitiator([]byte("sid"), identities[0].(types.AuthKey), protocol, []byte("hello world"))
	require.Error(t, err)
}
