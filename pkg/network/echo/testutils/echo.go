package testutils

import (
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/network/echo"
	"github.com/stretchr/testify/require"
)

func MakeEchoParticipants(message []byte, protocol types.Protocol, prng io.Reader, sessionId []byte) ([]*echo.Participant, error) {
	baseParticipants, err := ttu.MakeParticipants(protocol, prng, sessionId)
	if err != nil {
		return nil, err
	}
	initiator, err := echo.NewInitiator(baseParticipants[0], message)
	if err != nil {
		return nil, err
	}
	responders := make([]*echo.Participant, len(baseParticipants)-1)
	for i := 1; i < len(baseParticipants); i++ {
		responders[i-1], err = echo.NewResponder(baseParticipants[i], initiator.IdentityKey())
		if err != nil {
			return nil, err
		}
	}
	allParticipants := []*echo.Participant{initiator}
	allParticipants = append(allParticipants, responders...)
	return allParticipants, nil
}

func RunEcho(allParticipants []*echo.Participant) (results [][]byte, err error) {
	r1OutMessages := make([]network.RoundMessages[types.Protocol, *echo.Round1P2P], len(allParticipants))
	for i, participant := range allParticipants {
		r1OutMessage, err := participant.Round1()
		if err != nil {
			return nil, err
		}
		r1OutMessages[i] = r1OutMessage
	}
	r2InMessages := ttu.MapUnicastO2I(allParticipants, r1OutMessages)
	r2OutMessageRound := make([]network.RoundMessages[types.Protocol, *echo.Round2P2P], len(allParticipants))
	for i, participant := range allParticipants {
		r1InMessage, _ := r2InMessages[i].Get(allParticipants[0].IdentityKey())
		r2OutMessages, err := participant.Round2(r1InMessage)
		if err != nil {
			return nil, err
		}
		r2OutMessageRound[i] = r2OutMessages
	}
	r3InMessages := ttu.MapUnicastO2I(allParticipants, r2OutMessageRound)
	outputMessages := make([][]byte, len(allParticipants))
	for i, participant := range allParticipants {
		nonNilR3InMessages := network.NewRoundMessages[types.Protocol, *echo.Round2P2P]()
		for mj := range r3InMessages[i].Iter() {
			if mj.Value != nil {
				nonNilR3InMessages.Put(mj.Key, mj.Value)
			}
		}
		outputMessages[i], err = participant.Round3(nonNilR3InMessages)
		if err != nil {
			return nil, err
		}
	}
	return outputMessages, nil
}

func ValidateEcho(t *testing.T, outputMessages [][]byte) {
	t.Helper()
	for i := 1; i < len(outputMessages); i++ {
		require.Equal(t, outputMessages[0], outputMessages[i],
			"Participant %d output message does not match initiator output message", i)
	}
}
