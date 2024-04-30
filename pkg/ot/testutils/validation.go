package ot_testutils

import (
	"bytes"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

// ValidateOT checks the results of a ROT/OT, testing that r_x = s_{x} = s_1 • x + s_0 • (1-x).
func ValidateOT(
	Xi int, // number of OTe messages in the batch
	L int, // number of OTe elements per message
	senderMessages [][2]ot.Message, // sender's input in OT, the MessagePair (s_0, s_1)
	receiverChoiceBits ot.PackedBits, // receiver's input, the Choice bits x
	receiverChosenMessages []ot.Message, // receiver's output, the ChosenMessage (r_x)
) error {
	// Check length matching
	if len(receiverChoiceBits) != Xi/8 || len(receiverChosenMessages) != Xi || len(senderMessages) != Xi {
		return errs.NewLength("ROT output length mismatch (should be %d, is: %d)",
			ot.KappaBytes, len(receiverChoiceBits))
	}
	// Check baseOT results
	for i := 0; i < Xi; i++ {
		if len(receiverChosenMessages[i]) != L || len(senderMessages[i][0]) != L || len(senderMessages[i][1]) != L {
			return errs.NewLength("ROT output message length mismatch (should be %d, is: %d, %d, %d)",
				L, len(receiverChosenMessages[i]), len(senderMessages[i][0]), len(senderMessages[i][1]))
		}
		choice := receiverChoiceBits.Select(i)
		if !bytes.Equal(receiverChosenMessages[i][0][:], senderMessages[i][choice][0][:]) {
			return errs.NewVerification("ROT output mismatch for index %d", i)
		}
	}
	return nil
}

// ValidateCOT checks the results of a Correlated OT, testing that z_A + z_B = x • α.
func ValidateCOT(
	Xi int, // number of OTe messages in the batch
	L int, // number of OTe elements per message
	receiverChoices ot.PackedBits, // (x)
	senderInput []ot.CorrelatedMessage, // (a)
	receiverOutput []ot.CorrelatedMessage, // (z_B)
	senderOutput []ot.CorrelatedMessage, // (z_A)
) error {
	if len(receiverChoices)*8 != Xi || len(receiverOutput) != Xi || len(senderOutput) != Xi || len(senderInput) != Xi {
		return errs.NewLength("COTe input/output batch length mismatch (%d, %d, %d, %d, %d)",
			Xi, len(receiverChoices)*8, len(receiverOutput), len(senderOutput), len(senderInput))
	}
	// Check correlation in COTe results
	for j := 0; j < Xi; j++ {
		if len(receiverOutput[j]) != L || len(senderOutput[j]) != L || len(senderInput[j]) != L {
			return errs.NewLength("COTe input/output message %d length mismatch (should be %d, is: %d, %d, %d)",
				j, L, len(receiverOutput[j]), len(senderOutput[j]), len(senderInput[j]))
		}
		x := receiverChoices.Select(j)
		for l := 0; l < L; l++ {
			// Check each correlation z_A = x • α - z_B
			z_A := senderOutput[j][l]
			z_B := receiverOutput[j][l]
			alpha := senderInput[j][l]
			if x != 0 {
				if z_A.Cmp(alpha.Sub(z_B)) != 0 {
					return errs.NewVerification("COTe output mismatch for index %d", j)
				}
			} else {
				if z_A.Cmp(z_B.Neg()) != 0 {
					return errs.NewVerification("COTe output mismatch for index %d", j)
				}
			}
		}
	}
	return nil
}

func ErrorOnlyInvalidParameter(t *testing.T, err error, Xi int, L int, Curve curves.Curve) {
	// If parameter is invalid, check that the error is the expected one.
	// If parameter is valid, check that the error is nil.

}
