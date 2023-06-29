package softspoken

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/simplest"
)

func TestBinaryMult(t *testing.T) {
	for i := 0; i < 100; i++ {
		temp := make([]byte, 32)
		_, err := rand.Read(temp)
		require.NoError(t, err)
		expected := make([]byte, 32)
		copy(expected, temp)
		// this test is based on Fermat's little theorem.
		// the multiplicative group of units of a finite field has order |F| - 1
		// (in fact, it's necessarily cyclic; see e.g. https://math.stackexchange.com/a/59911, but this test doesn't rely on that fact)
		// thus raising any element to the |F|th power should yield that element itself.
		// this is a good test because it relies on subtle facts about the field structure, and will fail if anything goes wrong.
		for j := 0; j < 256; j++ {
			expected = binaryFieldMul(expected, expected)
		}
		require.Equal(t, temp, expected)
	}
}

func TestCOTExtension(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		uniqueSessionId := [simplest.DigestSize]byte{}
		_, err := rand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		baseOtSenderOutput, baseOtReceiverOutput, err := RunSimplestOT(t, curve, Kappa, uniqueSessionId)
		require.NoError(t, err)
		for i := 0; i < Kappa; i++ {
			require.Equal(t, baseOtReceiverOutput.OneTimePadDecryptionKey[i], baseOtSenderOutput.OneTimePadEncryptionKeys[i][baseOtReceiverOutput.RandomChoiceBits[i]])
		}

		sender := NewCOtSender(baseOtReceiverOutput, curve)
		receiver := NewCOtReceiver(baseOtSenderOutput, curve)
		choice := [LBytes]byte{} // receiver's input, namely choice vector. just random
		_, err = rand.Read(choice[:])
		require.NoError(t, err)
		input := [L][KeyCount]curves.Scalar{} // sender's input, namely integer "sums" in case w_j == 1.
		for i := 0; i < L; i++ {
			for j := 0; j < KeyCount; j++ {
				input[i][j] = curve.Scalar.Random(rand.Reader)
				require.NoError(t, err)
			}
		}
		firstMessage, err := receiver.Round1Initialize(uniqueSessionId, choice)
		require.NoError(t, err)
		responseTau, err := sender.Round2Transfer(uniqueSessionId, input, firstMessage)
		require.NoError(t, err)
		err = receiver.Round3Transfer(responseTau)
		require.NoError(t, err)
		for j := 0; j < L; j++ {
			bit := simplest.ExtractBitFromByteVector(choice[:], j) == 1
			for k := 0; k < KeyCount; k++ {
				temp := sender.OutputAdditiveShares[j][k].Add(receiver.OutputAdditiveShares[j][k])
				if bit {
					require.Equal(t, temp, input[j][k])
				} else {
					require.Equal(t, temp, curve.Scalar.Zero())
				}
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
