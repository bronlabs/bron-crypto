package ot_testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

func FunctionalityROT(
	Xi int, // number of OTe messages in the batch
	L int, // number of OTe elements per message
	receiverChoices ot.PackedBits, // receiver's input, the Choice bits x
	rng io.Reader, // random number generator
) (
	senderMessages [][2]ot.Message, // sender's output in ROT, the MessagePair (s_0, s_1)
	receiverChosenMessages []ot.Message, // receiver's output, the ChosenMessage (r_x)
	err error,
) {
	// Check length matching
	if len(receiverChoices) != Xi/8 {
		return nil, nil, errs.NewLength("ROT receiver choices length mismatch (should be %d, is: %d)",
			Xi/8, len(receiverChoices))
	}
	// Generate random sender messages
	senderMessages = make([][2]ot.Message, Xi)
	receiverChosenMessages = make([]ot.Message, Xi)
	for i := range Xi {
		senderMessages[i] = [2]ot.Message{make(ot.Message, L), make(ot.Message, L)}
		receiverChosenMessages[i] = make(ot.Message, L)
		for l := range L {
			_, err0 := io.ReadFull(rng, senderMessages[i][0][l][:])
			_, err1 := io.ReadFull(rng, senderMessages[i][1][l][:])
			if err0 != nil || err1 != nil {
				return nil, nil, errs.WrapRandomSample(err, "could not generate random message")
			}
			copy(receiverChosenMessages[i][l][:], senderMessages[i][receiverChoices.Select(i)][l][:])
		}
	}
	return senderMessages, receiverChosenMessages, nil
}

// FunctionalityOT computes the result of a (R)OT, testing that r_x = s_{x} = s_1 • x + s_0 • (1-x).
func FunctionalityOT(
	Xi int, // number of OTe messages in the batch
	L int, // number of OTe elements per message
	senderMessages [][2]ot.Message, // sender's input in OT, the MessagePair (s_0, s_1)
	receiverChoices ot.PackedBits, // receiver's input, the Choice bits x
) (
	receiverChosenMessages []ot.Message,
	err error,
) {
	// Check length matching
	if len(receiverChoices) != Xi/8 {
		return nil, errs.NewLength("ROT receiver choices length mismatch (should be %d, is: %d)",
			Xi/8, len(receiverChoices))
	}
	if len(senderMessages) != Xi {
		return nil, errs.NewLength("ROT sender messages length mismatch (should be %d, is: %d)",
			Xi, len(senderMessages))
	}
	// Compute chosen message
	receiverChosenMessages = make([]ot.Message, Xi)
	for i := 0; i < Xi; i++ {
		if len(senderMessages[i][0]) != L || len(senderMessages[i][1]) != L {
			return nil, errs.NewLength("ROT output message length mismatch (should be %d, is: %d, %d)",
				L, len(senderMessages[i][0]), len(senderMessages[i][1]))
		}
		choice := receiverChoices.Select(i)
		for l := range L {
			copy(receiverChosenMessages[i][l][:], senderMessages[i][choice][l][:])
		}
	}
	return receiverChosenMessages, nil
}

// FunctionalityCOT computes the results of a Correlated OT: z_A + z_B = x • α.
func FunctionalityCOT(
	Xi int, // number of OTe messages in the batch
	L int, // number of OTe elements per message
	receiverChoices ot.PackedBits, // (x)
	senderInput []ot.CorrelatedMessage, // (a)
	rng io.Reader, // random number generator
) (
	receiverOutput []ot.CorrelatedMessage, // (z_B)
	senderOutput []ot.CorrelatedMessage, // (z_A)
	err error,
) {
	if len(receiverChoices)*8 != Xi || len(receiverOutput) != Xi || len(senderOutput) != Xi || len(senderInput) != Xi {
		return nil, nil, errs.NewLength("COTe input/output batch length mismatch (%d, %d, %d, %d, %d)",
			Xi, len(receiverChoices)*8, len(receiverOutput), len(senderOutput), len(senderInput))
	}
	senderOutput = make([]ot.CorrelatedMessage, Xi)
	receiverOutput = make([]ot.CorrelatedMessage, Xi)
	for j := 0; j < Xi; j++ {
		if len(receiverOutput[j]) != L || len(senderOutput[j]) != L || len(senderInput[j]) != L {
			return nil, nil, errs.NewLength("COTe input/output message %d length mismatch (should be %d, is: %d, %d, %d)",
				j, L, len(receiverOutput[j]), len(senderOutput[j]), len(senderInput[j]))
		}
		x := receiverChoices.Select(j)
		senderOutput[j] = make(ot.CorrelatedMessage, L)
		receiverOutput[j] = make(ot.CorrelatedMessage, L)
		for l := 0; l < L; l++ {
			// Compute each correlation z_A = x • α - z_B
			senderOutput[j][l], err = senderInput[j][l].ScalarField().Random(rng) // z_A
			receiverOutput[j][l] = senderOutput[j][l].Neg()                       // z_B
			if x != 0 {
				receiverOutput[j][l].Add(senderInput[j][l]) // z_B = α - z_B
			}
		}
	}
	return receiverOutput, senderOutput, nil
}
