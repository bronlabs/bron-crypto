package softspoken

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/simplest"
)

func TestCOTExtension(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
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

		// Setup COTe
		sender := NewCOtSender(baseOtReceiverOutput, curve, false)
		receiver := NewCOtReceiver(baseOtSenderOutput, curve, false)
		choice := [LBytes]byte{} // receiver's input, the Choice bits x
		_, err = rand.Read(choice[:])
		require.NoError(t, err)
		inputOpt := [L]curves.Scalar{} // sender's input, the InputOpt α
		for i := 0; i < L; i++ {
			inputOpt[i] = curve.Scalar.Random(rand.Reader)
			require.NoError(t, err)
		}

		round1Output, err := receiver.Round1Extend(uniqueSessionId, choice)
		require.NoError(t, err)
		round2Output, err := sender.Round2Extend(uniqueSessionId, round1Output, inputOpt)
		require.NoError(t, err)

		var prgSync, bitCorr [SigmaBytes]byte
		for i := 0; i < Kappa; i++ {
			for j := 0; j < (M + 1); j++ {
				// Check the extended options: t^i_{Δ_i} = Δ_i•t^i_1 ⊕ (1⊕Δ_i)•t^i_0
				choiceBit := sender.baseOtRecOutputs.RandomChoiceBits[i]
				XORbits(prgSync[:],
					sender.ExtChosenOpt[i][j*SigmaBytes:(j+1)*SigmaBytes],
					receiver.ExtOptions[choiceBit][i][j*SigmaBytes:(j+1)*SigmaBytes])
				require.Zero(t, prgSync)
				// Check each bit-level correlation q_i = t^i_0 ⊕ x • Δ_i
				XORbits(bitCorr[:],
					sender.ExtCorrelations[i][j*SigmaBytes:(j+1)*SigmaBytes],
					receiver.ExtOptions[0][i][j*SigmaBytes:(j+1)*SigmaBytes])
				if choiceBit != 0 {
					XORbits(bitCorr[:],
						bitCorr[:],
						receiver.ExtPackChoices[j*SigmaBytes:(j+1)*SigmaBytes])
				}
				require.Zero(t, bitCorr)
			}
		}
		round3Output, err := receiver.Round3ProveConsistency(round2Output)
		require.NoError(t, err)
		err = sender.Round4CheckConsistency(round2Output, round3Output)
		require.NoError(t, err)

		for j := 0; j < L; j++ {
			// Check each correlation z_B = x • α + z_A
			if UnpackBit(j, choice[:]) != 0 {
				require.Equal(t, receiver.OutCorrelations[j], inputOpt[j].Sub(sender.OutDeltaOpt[j]))
			} else {
				require.Equal(t, receiver.OutCorrelations[j], sender.OutDeltaOpt[j].Neg())
			}
		}
	}
}

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
//	R: x ---┐                            ┌---> R: z_B
//	        ├--- COTe_{κ, L, M}(x, α)---┤
//	S: α ---┘                            └---> S: z_A
func RunSoftspokenCOTe(
	t *testing.T, curve *curves.Curve, uniqueSessionId [simplest.DigestSize]byte,
	choice [LBytes]byte, // receiver's input, the Choice bits x
	inputOpt [L]curves.Scalar, // sender's input, the InputOpt α
) (z_A *[L]curves.Scalar, z_B *[L]curves.Scalar, err error) {
	t.Helper()
	// BaseOTs
	batchSize := Kappa
	baseOtSenderOutput, baseOtReceiverOutput, err := RunSimplestOT(t, curve, batchSize, uniqueSessionId)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "base OT in run softspoken COTe")
	}
	// Setup COTe
	sender := NewCOtSender(baseOtReceiverOutput, curve, false)
	receiver := NewCOtReceiver(baseOtSenderOutput, curve, false)

	// Run COTe
	round1Output, err := receiver.Round1Extend(uniqueSessionId, choice)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 1 in run softspoken COTe")
	}
	round2Output, err := sender.Round2Extend(uniqueSessionId, round1Output, inputOpt)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 2 in run softspoken COTe")
	}
	round3Output, err := receiver.Round3ProveConsistency(round2Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "receiver round 3 in run softspoken COTe")
	}
	err = sender.Round4CheckConsistency(round2Output, round3Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "sender round 4 in run softspoken COTe")
	}
	return &sender.OutDeltaOpt, &receiver.OutCorrelations, nil
}
