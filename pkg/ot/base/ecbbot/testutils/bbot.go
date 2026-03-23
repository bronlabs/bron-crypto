package testutils

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/bronlabs/errs-go/errs"
)

// RunBBOT runs the full batched base OT protocol.
func RunBBOT[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](tb testing.TB, xi, l int, group algebra.PrimeGroup[GE, SE], prng io.Reader) (*ecbbot.SenderOutput[SE], *ecbbot.ReceiverOutput[SE], error) {
	tb.Helper()

	suite, err := ecbbot.NewSuite(xi, l, group)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("constructing OT suite in run BatchedBaseOT")
	}

	const senderID = 1
	const receiverID = 2
	quorum := hashset.NewComparable[sharing.ID](senderID, receiverID).Freeze()
	ctxs := session_testutils.MakeRandomContexts(tb, quorum, prng)

	sender, err := ecbbot.NewSender(ctxs[senderID], suite, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("constructing OT sender in run BatchedBaseOT")
	}
	receiver, err := ecbbot.NewReceiver(ctxs[receiverID], suite, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("constructing OT receiver in run BatchedBaseOT")
	}

	// Run the protocol
	// R1
	r1Out, err := sender.Round1()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("sender round 1 in run BatchedBaseOT")
	}

	// R2
	receiverInput := make([]byte, xi/8)
	if _, err := io.ReadFull(prng, receiverInput); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("reading receiver input")
	}
	r2Out, receiverOutput, err := receiver.Round2(r1Out, receiverInput)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("receiver round 2 in run BatchedBaseOT")
	}

	// R3
	senderOutput, err := sender.Round3(r2Out)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("sender round 3 in run BatchedBaseOT")
	}
	return senderOutput, receiverOutput, nil
}

func ValidateOT[S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	xi int, // number of OTe messages in the batch
	l int, // number of OTe elements per message
	senderOutput *ecbbot.SenderOutput[S],
	receiverOutput *ecbbot.ReceiverOutput[S],
) {
	tb.Helper()

	// Check length matching
	if len(receiverOutput.Choices) != xi/8 || len(receiverOutput.Messages) != xi || len(senderOutput.Messages) != xi {
		require.FailNow(tb, "length mismatch")
	}

	// Check baseOT results
	for xiI := range xi {
		if len(receiverOutput.Messages[xiI]) != l || len(senderOutput.Messages[xiI][0]) != l || len(senderOutput.Messages[xiI][1]) != l {
			require.FailNow(tb, "length mismatch")
		}
		choice := (receiverOutput.Choices[xiI/8] >> (xiI % 8)) & 0b1
		for li := range l {
			received := receiverOutput.Messages[xiI][li]
			sentChosen := senderOutput.Messages[xiI][choice][li]
			sentNotChosen := senderOutput.Messages[xiI][1-choice][li]
			require.True(tb, sentChosen.Equal(received))
			require.False(tb, sentNotChosen.Equal(received))
		}
	}
}
