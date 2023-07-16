package softspoken

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/simplest"
)

var curveInstances = []*curves.Curve{
	curves.K256(),
	curves.P256(),
}

func TestOTextension(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		uniqueSessionId := [simplest.DigestSize]byte{}
		_, err := rand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := RunSimplestOT(t, curve, Kappa, uniqueSessionId)
		require.NoError(t, err)
		for i := 0; i < Kappa; i++ {
			require.Equal(t, baseOtReceiverOutput.OneTimePadDecryptionKey[i], baseOtSenderOutput.OneTimePadEncryptionKeys[i][baseOtReceiverOutput.RandomChoiceBits[i]])
		}

		// Set OTe inputs
		choices := OTeInputChoices{} // receiver's input, the Choice bits x
		_, err = rand.Read(choices[:])
		require.NoError(t, err)

		// Run OTe
		oTeSenderOutput, oTeReceiverOutput, err := RunSoftspokenOTe(t, curve, uniqueSessionId, baseOtSenderOutput, baseOtReceiverOutput, &choices)
		require.NoError(t, err)

		// Check OTe result
		for i := 0; i < Kappa; i++ {
			// Check that v_x = v_1 • x + v_0 • (1-x)
			if UnpackBit(i, choices[:]) != 0 {
				require.Equal(t, oTeSenderOutput[1][i], oTeReceiverOutput[i])
			} else {
				require.Equal(t, oTeSenderOutput[0][i], oTeReceiverOutput[i])
			}
		}
	}
}

func TestCOTextensionWithForcedReuse(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		useForcedReuse := true
		inputBatchLen := 128
		uniqueSessionId := [simplest.DigestSize]byte{}
		_, err := rand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := RunSimplestOT(t, curve, Kappa, uniqueSessionId)
		require.NoError(t, err)
		for i := 0; i < Kappa; i++ {
			require.Equal(t, baseOtReceiverOutput.OneTimePadDecryptionKey[i], baseOtSenderOutput.OneTimePadEncryptionKeys[i][baseOtReceiverOutput.RandomChoiceBits[i]])
		}

		// Set COTe inputs
		choices := OTeInputChoices{} // receiver's input, the Choice bits x
		_, err = rand.Read(choices[:])
		require.NoError(t, err)
		inputOpts := make([]COTeInputOpt, inputBatchLen) // sender's input, the InputOpt α
		for k := 0; k < inputBatchLen; k++ {
			for i := 0; i < Eta; i++ {
				inputOpts[k][i] = curve.Scalar.Random(rand.Reader)
				require.NoError(t, err)
			}
		}

		// Run COTe
		cOTeSenderOutputs, cOTeReceiverOutputs, err := RunSoftspokenCOTe(t, useForcedReuse, curve, uniqueSessionId, baseOtSenderOutput, baseOtReceiverOutput, &choices, inputOpts)
		require.NoError(t, err)

		// Check COTe result
		for k := 0; k < inputBatchLen; k++ {
			for j := 0; j < Eta; j++ {
				// Check each correlation z_B = x • α + z_A
				if UnpackBit(j, choices[:]) != 0 {
					require.Equal(t, cOTeReceiverOutputs[k][j], inputOpts[k][j].Sub(cOTeSenderOutputs[k][j]))
				} else {
					require.Equal(t, cOTeReceiverOutputs[k][j], cOTeSenderOutputs[k][j].Neg())
				}
			}
		}
	}
}

func TestCOTextension(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		useForcedReuse := false
		// inputBatchLen := 1 // Must be 1 if useForcedReuse is false. Set L>1 for higher batch sizes, or loop over inputBatchLen.
		uniqueSessionId := [simplest.DigestSize]byte{}
		_, err := rand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := RunSimplestOT(t, curve, Kappa, uniqueSessionId)
		require.NoError(t, err)
		for i := 0; i < Kappa; i++ {
			require.Equal(t, baseOtReceiverOutput.OneTimePadDecryptionKey[i], baseOtSenderOutput.OneTimePadEncryptionKeys[i][baseOtReceiverOutput.RandomChoiceBits[i]])
		}

		// Set COTe inputs
		choices := OTeInputChoices{} // receiver's input, the Choice bits x
		_, err = rand.Read(choices[:])
		require.NoError(t, err)
		inputOpt := COTeInputOpt{} // sender's input, the InputOpt α
		for i := 0; i < Eta; i++ {
			inputOpt[i] = curve.Scalar.Random(rand.Reader)
			require.NoError(t, err)
		}
		inputOpts := []COTeInputOpt{inputOpt} // A slice of length 1 is required if useForcedReuse is false.

		// Run COTe
		cOTeSenderOutputs, cOTeReceiverOutputs, err := RunSoftspokenCOTe(t, useForcedReuse, curve, uniqueSessionId, baseOtSenderOutput, baseOtReceiverOutput, &choices, inputOpts)
		require.NoError(t, err)

		// Check COTe result
		for j := 0; j < Eta; j++ {
			// Check each correlation z_B = x • α + z_A
			if UnpackBit(j, choices[:]) != 0 {
				require.Equal(t, cOTeReceiverOutputs[0][j], inputOpt[j].Sub(cOTeSenderOutputs[0][j]))
			} else {
				require.Equal(t, cOTeReceiverOutputs[0][j], cOTeSenderOutputs[0][j].Neg())
			}
		}

	}
}

// ========================================================================== //
// =========================== RUN FUNCTIONS ================================ //
// ========================================================================== //
// RunSimplestOT is a utility function encapsulating the entire process of
// running a base OT, so that other tests can use it / bootstrap themselves.
// As a black box, this function uses randomized inputs, and does:
//
//	.             ┌---> R: k^i_{Δ_i}, Δ_i
//	BaseOT_{κ}()--┤
//	.             └---> S: k^i_0, k^i_1
func RunSimplestOT(t *testing.T, curve *curves.Curve, batchSize int, uniqueSessionId [simplest.DigestSize]byte) (*simplest.SenderOutput, *simplest.ReceiverOutput, error) {
	t.Helper()
	receiver, err := simplest.NewReceiver(curve, batchSize, uniqueSessionId, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT receiver in run simplest OT")
	}
	sender, err := simplest.NewSender(curve, batchSize, uniqueSessionId, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing OT sender in run simplest OT")
	}
	proof, err := sender.Round1ComputeAndZkpToPublicKey()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 1 in run simplest OT")
	}
	receiversMaskedChoice, err := receiver.Round2VerifySchnorrAndPadTransfer(proof)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 2 in run simplest OT")
	}
	challenge, err := sender.Round3PadTransfer(receiversMaskedChoice)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 3 in run simplest OT")
	}
	challengeResponse := receiver.Round4RespondToChallenge(challenge)
	challengeOpenings, err := sender.Round5Verify(challengeResponse)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 5 in run simplest OT")
	}
	err = receiver.Round6Verify(challengeOpenings)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 6 in run simplest OT")
	}
	return sender.Output, receiver.Output, nil
}

// RunSoftspokenCOTe is a utility function encapsulating the entire process of
// running a SoftspokenOT extension and derandomizing its result.
// As a black box, this function does:
//
//		R: x ---┐                           ┌---> R: z_B
//		        ├--- COTe_{κ, L, M}(x, α)---┤
//		S: α ---┘                           └---> S: z_A
//	 s.t. z_A = x • α - z_B
//
// If useForcedReuse: use a single OTe batch for all the inputOpt batches.
// NOTE: it should only be used by setting L=1 in "participants.go"
func RunSoftspokenCOTe(t *testing.T,
	useForcedReuse bool,
	curve *curves.Curve,
	uniqueSessionId [simplest.DigestSize]byte,
	baseOtSenderOutput *simplest.SenderOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *simplest.ReceiverOutput, // baseOT seeds for OTe sender
	choices *OTeInputChoices, // receiver's input, the Choice bits x
	inputOpts []COTeInputOpt, // sender's input, the InputOpt batches of α
) (cOTeSenderOutputs []COTeSenderOutput, cOTeReceiverOutputs []COTeReceiverOutput, err error) {
	t.Helper()

	// Setup COTe
	sender, err := NewCOtSender(baseOtReceiverOutput, uniqueSessionId, nil, curve, useForcedReuse)
	require.NoError(t, err)
	receiver, err := NewCOtReceiver(baseOtSenderOutput, uniqueSessionId, nil, curve, useForcedReuse)
	require.NoError(t, err)

	// Run COTe
	extPackedChoices, oTeReceiverOutput, round1Output, err :=
		receiver.Round1ExtendAndProveConsistency(choices)
	require.NoError(t, err)
	_, cOTeSenderOutputs, round2Output, err :=
		sender.Round2ExtendAndCheckConsistency(round1Output, inputOpts)
	require.NoError(t, err)
	cOTeReceiverOutputs, err = receiver.Round3Derandomize(round2Output, extPackedChoices, oTeReceiverOutput)
	require.NoError(t, err)
	return cOTeSenderOutputs, cOTeReceiverOutputs, nil
}

// RunSoftspokenOTe is a utility function encapsulating the entire process of
// running a random OT extension without derandomization.
// As a black box, this function does:
//
//		R: x ---┐                        ┌---> R: (v_x)
//		        ├--- COTe_{κ, L, M}(x)---┤
//		S:   ---┘                        └---> S: (v_0, v_1)
//	 s.t. v_x = v_1 • (x) + v_0 • (1-x)
func RunSoftspokenOTe(t *testing.T,
	curve *curves.Curve,
	uniqueSessionId [simplest.DigestSize]byte,
	baseOtSenderOutput *simplest.SenderOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *simplest.ReceiverOutput, // baseOT seeds for OTe sender
	choices *OTeInputChoices, // receiver's input, the Choice bits x
) (oTeSenderOutputs *OTeSenderOutput, oTeReceiverOutputs *OTeReceiverOutput, err error) {
	t.Helper()
	// Setup OTe
	useForcedReuse := false
	sender, err := NewCOtSender(baseOtReceiverOutput, uniqueSessionId, nil, curve, useForcedReuse)
	require.NoError(t, err)
	receiver, err := NewCOtReceiver(baseOtSenderOutput, uniqueSessionId, nil, curve, useForcedReuse)
	require.NoError(t, err)

	// Run OTe
	_, oTeReceiverOutput, round1Output, err :=
		receiver.Round1ExtendAndProveConsistency(choices)
	require.NoError(t, err)
	oTeSenderOutput, _, _, err :=
		sender.Round2ExtendAndCheckConsistency(round1Output, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	return oTeSenderOutput, oTeReceiverOutput, nil
}
