package simplest_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/simplest"
	"github.com/stretchr/testify/require"
)

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

func TestOtOnMultipleCurves(t *testing.T) {
	t.Parallel()
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		batchSize := 256
		hashKeySeed := [32]byte{}
		_, err := rand.Read(hashKeySeed[:])
		require.NoError(t, err)
		sender, receiver, err := RunSimplestOT(t, curve, batchSize, hashKeySeed)
		require.NoError(t, err)

		for i := 0; i < batchSize; i++ {
			require.Equal(t, receiver.OneTimePadDecryptionKey[i], sender.OneTimePadEncryptionKeys[i][receiver.RandomChoiceBits[i]])
		}

		// Transfer messages
		messages := make([][2][32]byte, batchSize)
		for i := 0; i < batchSize; i++ {
			messages[i] = [2][32]byte{
				sha256.Sum256([]byte(fmt.Sprintf("message[%d][0]", i))),
				sha256.Sum256([]byte(fmt.Sprintf("message[%d][1]", i))),
			}
		}
		ciphertexts, err := sender.Encrypt(messages)
		require.NoError(t, err)
		decrypted, err := receiver.Decrypt(ciphertexts)
		require.NoError(t, err)

		for i := 0; i < batchSize; i++ {
			choice := receiver.RandomChoiceBits[i]
			require.Equal(t, messages[i][choice], decrypted[i])
			require.NotEqual(t, messages[i][1-choice], decrypted[i])
		}
	}
}
