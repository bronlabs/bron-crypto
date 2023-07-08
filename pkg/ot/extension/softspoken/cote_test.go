package softspoken

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	uint128 "github.com/copperexchange/crypto-primitives-go/pkg/core/modular"
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
		sender := NewCOtSender(baseOtReceiverOutput, curve)
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

		for i := 0; i < Kappa; i++ {
			for j := 0; j < (M + 1); j++ {
				// Check the extended options: t^i_{Δ_i} = Δ_i•t^i_1 ⊕ (1⊕Δ_i)•t^i_0
				prgSync := uint128.FromBytes(sender.ExtChosenOpt[i][j*SBytes : (j+1)*SBytes]).Sub(
					uint128.FromBytes(receiver.ExpOptions[sender.baseOtRecOutputs.RandomChoiceBits[i]][i][j*SBytes : (j+1)*SBytes]))
				require.Zero(t, prgSync)
				// Check each bit-level correlation q_i = t^i_0 ⊕ x • Δ_i
				bitCorr := uint128.FromBytes(sender.ExtCorrelations[i][j*SBytes : (j+1)*SBytes]).Sub(
					uint128.FromBytes(receiver.ExpOptions[0][i][j*SBytes : (j+1)*SBytes]))
				if sender.baseOtRecOutputs.RandomChoiceBits[i] != 0 {
					bitCorr = bitCorr.Sub(uint128.FromBytes(receiver.ExtPackChoices[j*SBytes : (j+1)*SBytes]))
				}
				require.Zero(t, bitCorr)
			}
		}
		round3Output, err := receiver.Round3ProveConsistency(round2Output)
		require.NoError(t, err)

		err = sender.Round4CheckConsistency(round2Output, round3Output)
		require.NoError(t, err)

		for j := 0; j < L; j++ {
			// Check each correlation z_A = x • α - z_B
			if UnpackBit(j, choice[:]) {
				require.Equal(t, sender.OutDeltaOpt[j], receiver.OutCorrelations[j].Sub(inputOpt[j]))
			} else {
				require.Equal(t, sender.OutDeltaOpt[j], receiver.OutCorrelations[j])
			}
		}
	}
}

// RunSimplestOT is a utility function used _only_ during various tests.
// essentially, it encapsulates the entire process of running a base OT, so that other tests can use it / bootstrap themselves.
// it handles the creation of the base OT sender and receiver, as well as orchestrates the rounds on them;
// it returns their outsputs, so that others can use them.
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
