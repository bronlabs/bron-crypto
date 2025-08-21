package testutils

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/stretchr/testify/require"
)

// RunBBOT runs the full batched base OT protocol.
func RunBBOT[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](chi, l int, group algebra.PrimeGroup[GE, SE], sessionId network.SID, tape transcripts.Transcript, prng io.Reader) (*ecbbot.SenderOutput[SE], *ecbbot.ReceiverOutput[SE], error) {
	//protocol, err := types.NewProtocol(curve, hashset.NewHashableHashSet(senderAuthKey.(types.IdentityKey), receiverAuthKey.(types.IdentityKey)))
	//if err != nil {
	//	return nil, nil, errs.WrapFailed(err, "could not construct ot protocol config")
	//}
	// Create participants
	sender, err := ecbbot.NewSender(sessionId, group, chi, l, tape.Clone(), prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in run BatchedBaseOT")
	}
	receiver, err := ecbbot.NewReceiver(sessionId, group, chi, l, tape.Clone(), prng)
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
	receiverInput := make([]byte, chi/8)
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

func ValidateOT[SE algebra.PrimeFieldElement[SE]](
	tb testing.TB,
	chi int, // number of OTe messages in the batch
	l int, // number of OTe elements per message
	senderOutput *ecbbot.SenderOutput[SE],
	receiverOutput *ecbbot.ReceiverOutput[SE],
) {
	tb.Helper()

	// Check length matching
	if len(receiverOutput.Choices) != chi/8 || len(receiverOutput.R) != chi || len(senderOutput.S) != chi {
		require.FailNow(tb, "length mismatch")
	}

	// Check baseOT results
	for chii := 0; chii < chi; chii++ {
		if len(receiverOutput.R[chii]) != l || len(senderOutput.S[chii][0]) != l || len(senderOutput.S[chii][1]) != l {
			require.FailNow(tb, "length mismatch")
		}
		choice := (receiverOutput.Choices[chii/8] >> (chii % 8)) & 0b1
		for li := 0; li < l; li++ {
			received := receiverOutput.R[chii][li]
			sentChosen := senderOutput.S[chii][choice][li]
			sentNotChosen := senderOutput.S[chii][1-choice][li]
			require.True(tb, sentChosen.Equal(received))
			require.False(tb, sentNotChosen.Equal(received))
		}
	}
}
