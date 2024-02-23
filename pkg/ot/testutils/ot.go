package testutils

import (
	"bytes"
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

/*.-------------------- RANDOM OBLIVIOUS TRANSFER (ROT) ---------------------.*/

// GenerateCOTinputs generates random inputs for Correlated OTs.
func GenerateOTinputs(Xi, L int) (
	receiverChoiceBits ot.ChoiceBits, // receiver's input, the Choice bits x
	senderMessages []ot.MessagePair, // sender's input in OT, the MessagePair (s_0, s_1)
	err error,
) {
	if L < 1 || Xi < 1 || Xi%8 != 0 {
		return nil, nil, errs.NewLength(" cannot generate random inputs for L=%d, Xi=%d", L, Xi)
	}
	receiverChoiceBits = make(ot.ChoiceBits, Xi/8)
	if _, err := crand.Read(receiverChoiceBits); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not generate random choice bits")
	}
	senderMessages = make([]ot.MessagePair, Xi)
	for i := 0; i < Xi; i++ {
		senderMessages[i] = ot.MessagePair{make(ot.Message, L), make(ot.Message, L)}
		for l := 0; l < L; l++ {
			_, err0 := crand.Read(senderMessages[i][0][l][:])
			_, err1 := crand.Read(senderMessages[i][1][l][:])
			if err0 != nil || err1 != nil {
				return nil, nil, errs.WrapRandomSample(err, "could not generate random message")
			}
		}
	}
	return receiverChoiceBits, senderMessages, nil
}

// ValidateOT checks the results of a ROT/OT, testing that r_x = s_{x} = s_1 • x + s_0 • (1-x).
func ValidateOT(
	Xi int, // number of OTe messages in the batch
	L int, // number of OTe elements per message
	senderMessages []ot.MessagePair, // sender's input in OT, the MessagePair (s_0, s_1)
	receiverChoiceBits ot.ChoiceBits, // receiver's input, the Choice bits x
	receiverChosenMessages []ot.ChosenMessage, // receiver's output, the ChosenMessage (r_x)
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

// GenerateCOTinputs generates random inputs for Correlated OTs.
func GenerateCOTinputs(Xi, L int, curve curves.Curve) (
	receiverChoiceBits ot.ChoiceBits, // receiver's input, the Choice bits x
	senderInput []ot.CorrelatedMessage, // sender's input, the MessagePair (α_0, α_1)
	err error,
) {
	if L < 1 || Xi < 1 || Xi%8 != 0 {
		return nil, nil, errs.NewLength(" cannot generate random inputs for L=%d, Xi=%d", L, Xi)
	}
	receiverChoiceBits = make(ot.ChoiceBits, Xi/8)
	if _, err := crand.Read(receiverChoiceBits); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not generate random choice bits")
	}
	if curve == nil { // Just need the input choices
		return receiverChoiceBits, nil, nil
	}
	senderInput = make([]ot.CorrelatedMessage, Xi)
	for j := 0; j < Xi; j++ {
		senderInput[j] = make(ot.CorrelatedMessage, L)
		for l := 0; l < L; l++ {
			senderInput[j][l], err = curve.Scalar().ScalarField().Random(crand.Reader)
			if err != nil {
				return nil, nil, errs.WrapRandomSample(err, "could not generate random scalar")
			}
		}
	}
	return receiverChoiceBits, senderInput, nil
}

// ValidateCOT checks the results of a Correlated OT, testing that z_A + z_B = x • α.
func ValidateCOT(
	Xi int, // number of OTe messages in the batch
	L int, // number of OTe elements per message
	receiverChoices ot.ChoiceBits, // (x)
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
