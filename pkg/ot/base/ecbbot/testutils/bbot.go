package testutils

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/stretchr/testify/require"
)

// RunBBOT runs the full batched base OT protocol.
func RunBBOT(senderAuthKey, receiverAuthKey types.AuthKey, Xi, L int, curve curves.Curve, uniqueSessionId []byte, prng io.Reader) (*ecbbot.SenderOutput, *ecbbot.ReceiverOutput, error) {
	protocol, err := types.NewProtocol(curve, hashset.NewHashableHashSet(senderAuthKey.(types.IdentityKey), receiverAuthKey.(types.IdentityKey)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct ot protocol config")
	}
	// Create participants
	sender, err := ecbbot.NewSender(senderAuthKey, protocol, Xi, L, uniqueSessionId, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in run BatchedBaseOT")
	}
	receiver, err := ecbbot.NewReceiver(receiverAuthKey, protocol, Xi, L, uniqueSessionId, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT receiver in run BatchedBaseOT")
	}

	// Run the protocol
	// R1
	r1Out, err := sender.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 1 in run BatchedBaseOT")
	}

	// R2
	receiverInput := make([]byte, Xi/8)
	if _, err := io.ReadFull(prng, receiverInput); err != nil {
		return nil, nil, errs.WrapFailed(err, "reading receiver input")
	}
	r2Out, receiverOutput, err := receiver.Round2(r1Out, receiverInput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 2 in run BatchedBaseOT")
	}

	// R3
	senderOutput, err := sender.Round3(r2Out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 3 in run BatchedBaseOT")
	}
	return senderOutput, receiverOutput, nil
}

func ValidateOT(
	tb testing.TB,
	Xi int, // number of OTe messages in the batch
	L int, // number of OTe elements per message
	senderOutput *ecbbot.SenderOutput,
	receiverOutput *ecbbot.ReceiverOutput,
) {
	tb.Helper()

	// Check length matching
	if len(receiverOutput.Choices) != Xi/8 || len(receiverOutput.R) != Xi || len(senderOutput.S) != Xi {
		require.FailNow(tb, "length mismatch")
	}

	// Check baseOT results
	for i := 0; i < Xi; i++ {
		if len(receiverOutput.R[i]) != L || len(senderOutput.S[i][0]) != L || len(senderOutput.S[i][1]) != L {
			require.FailNow(tb, "length mismatch")
		}
		choice := receiverOutput.Choices.Get(uint(i))
		for l := 0; l < L; l++ {
			received := receiverOutput.R[i][l]
			sentChosen := senderOutput.S[i][choice][l]
			sentNotChosen := senderOutput.S[i][1-choice][l]
			require.True(tb, sentChosen.Equal(received))
			require.False(tb, sentNotChosen.Equal(received))
		}
	}
}
