package vsot

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/proofs/schnorr"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

// The following aliases are not directly used within the round methods. They are helpful for composition.
type Round1P2P struct {
	Proof     *schnorr.Proof
	PublicKey curves.Point
}
type (
	Round2P2P = []ReceiversMaskedChoices
	Round3P2P = []OtChallenge
	Round4P2P = []OtChallengeResponse
	Round5P2P = []ChallengeOpening
	Round7P2P = [][KeyCount][DigestSize]byte
	Round8P2P = [][DigestSize]byte
)

// Round1ComputeAndZkpToPublicKey is the first phase of the protocol.
// computes and stores public key and returns the schnorr proof. serialised / packed.
// This implements step 1 of Protocol 7 of DKLs18, page 16.
func (sender *Sender) Round1ComputeAndZkpToPublicKey() (*schnorr.Proof, curves.Point, error) {
	var err error
	// Sample the secret key and compute the public key.
	sender.SecretKey = sender.Curve.Scalar.Random(rand.Reader)
	sender.PublicKey = sender.Curve.ScalarBaseMult(sender.SecretKey)

	// Generate the ZKP proof.
	// TODO: implement cloning
	clonedTranscript := merlin.NewTranscript("VSOT")
	prover, err := schnorr.NewProver(sender.Curve.NewGeneratorPoint(), sender.UniqueSessionId, clonedTranscript)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "constructing schnorr prover")
	}
	proof, publicKey, err := prover.Prove(sender.SecretKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "creating zkp proof for secret key in seed OT sender round 1")
	}
	return proof, publicKey, nil
}

// Round2VerifySchnorrAndPadTransfer verifies the schnorr proof of the public key sent by the sender, i.e., step 2),
// and then does receiver's "Pad Transfer" phase in OT, i.e., step 3), of Protocol 7 (page 16) of the paper.
func (receiver *Receiver) Round2VerifySchnorrAndPadTransfer(senderPublicKey curves.Point, proof *schnorr.Proof) ([]ReceiversMaskedChoices, error) {
	receiver.SenderPublicKey = senderPublicKey
	clonedTranscript := merlin.NewTranscript("VSOT")
	if err := schnorr.Verify(receiver.Curve.NewGeneratorPoint(), senderPublicKey, proof, receiver.UniqueSessionId, clonedTranscript); err != nil {
		return nil, errs.WrapVerificationFailed(err, "verifying schnorr proof in seed OT receiver round 2")
	}

	result := make([]ReceiversMaskedChoices, receiver.BatchSize)
	receiver.Output.OneTimePadDecryptionKey = make([]OneTimePadDecryptionKey, receiver.BatchSize)
	for i := 0; i < receiver.BatchSize; i++ {
		a := receiver.Curve.Scalar.Random(rand.Reader)
		// Computing `A := a . G + w . B` in constant time, by first computing option0 = a.G and option1 = a.G+B and then
		// constant time choosing one of them by first assuming that the output is option0, and overwrite it if the choice bit is 1.

		option0 := receiver.Curve.ScalarBaseMult(a)
		option0Bytes := option0.ToAffineCompressed()
		option1 := option0.Add(receiver.SenderPublicKey)
		option1Bytes := option1.ToAffineCompressed()

		result[i] = option0Bytes
		subtle.ConstantTimeCopy(receiver.Output.RandomChoiceBits[i], result[i], option1Bytes)
		// compute the internal rho
		rho := receiver.SenderPublicKey.Mul(a)
		output, err := hashing.Hash(sha3.New256, receiver.UniqueSessionId, []byte{byte(i)}, rho.ToAffineCompressed())
		if err != nil {
			return nil, errs.WrapFailed(err, "creating one time pad decryption keys")
		}
		copy(receiver.Output.OneTimePadDecryptionKey[i][:], output)
	}
	return result, nil
}

// Round3PadTransfer is the sender's "Pad Transfer" phase in OT; see steps 4 and 5 of page 16 of the paper.
// Returns the challenges xi.
func (sender *Sender) Round3PadTransfer(compressedReceiversMaskedChoice []ReceiversMaskedChoices) ([]OtChallenge, error) {
	var err error
	challenge := make([]OtChallenge, sender.BatchSize)
	sender.Output.OneTimePadEncryptionKeys = make([]OneTimePadEncryptionKeys, sender.BatchSize)
	negSenderPublicKey := sender.PublicKey.Neg()

	receiversMaskedChoice := make([]curves.Point, len(compressedReceiversMaskedChoice))
	for i := 0; i < len(compressedReceiversMaskedChoice); i++ {
		if receiversMaskedChoice[i], err = sender.Curve.Point.FromAffineCompressed(compressedReceiversMaskedChoice[i]); err != nil {
			return nil, errs.WrapDeserializationFailed(err, "uncompress the point")
		}
	}

	baseEncryptionKeyMaterial := make([]curves.Point, KeyCount)
	var hashedKey [KeyCount][DigestSize]byte

	for i := 0; i < sender.BatchSize; i++ {
		// Sender creates two options that will eventually be used as her encryption keys.
		// `baseEncryptionKeyMaterial[0]` and `baseEncryptionKeyMaterial[0]` correspond to rho_0 and rho_1 in the paper, respectively.
		baseEncryptionKeyMaterial[0] = receiversMaskedChoice[i].Mul(sender.SecretKey)

		receiverChoiceMinusSenderPublicKey := receiversMaskedChoice[i].Add(negSenderPublicKey)
		baseEncryptionKeyMaterial[1] = receiverChoiceMinusSenderPublicKey.Mul(sender.SecretKey)

		for k := 0; k < KeyCount; k++ {
			output, err := hashing.Hash(sha3.New256, sender.UniqueSessionId, []byte{byte(i)}, baseEncryptionKeyMaterial[k].ToAffineCompressed())
			if err != nil {
				return nil, errs.WrapFailed(err, "creating one time pad encryption keys")
			}
			copy(sender.Output.OneTimePadEncryptionKeys[i][k][:], output)

			// Compute a challenge by XORing the hash of the hash of the key. Not a typo ;)
			hashedKey[k] = sha3.Sum256(sender.Output.OneTimePadEncryptionKeys[i][k][:])
			hashedKey[k] = sha3.Sum256(hashedKey[k][:])
		}

		current, err := bitstring.XorBytes(hashedKey[0][:], hashedKey[1][:])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not xor bytes")
		}
		copy(challenge[i][:], current)
	}
	return challenge, nil
}

// Round4RespondToChallenge corresponds to initial round of the receiver's "Verify" phase; see step 6 of page 16 of the paper.
// this is just the start of Verification. In this round, the receiver outputs "rho'", which the sender will check.
func (receiver *Receiver) Round4RespondToChallenge(challenge []OtChallenge) ([]OtChallengeResponse, error) {
	// store to be used in future steps
	receiver.SenderChallenge = challenge
	// challengeResponses is Rho' in the paper.
	challengeResponses := make([]OtChallengeResponse, receiver.BatchSize)
	for i := 0; i < receiver.BatchSize; i++ {
		// Constant-time xor of the hashed key and the challenge, based on the choice bit.
		hashedKey := sha3.Sum256(receiver.Output.OneTimePadDecryptionKey[i][:])
		hashedKey = sha3.Sum256(hashedKey[:])
		challengeResponses[i] = hashedKey
		alternativeChallengeResponse, err := bitstring.XorBytes(receiver.SenderChallenge[i][:], hashedKey[:])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not xor bytes")
		}
		subtle.ConstantTimeCopy(receiver.Output.RandomChoiceBits[i], challengeResponses[i][:], alternativeChallengeResponse)
	}
	return challengeResponses, nil
}

// Round5Verify verifies the challenge response. If the verification passes, sender opens his challenges to the receiver.
// See step 7 of page 16 of the paper.
// Abort if Rho' != H(H(Rho^0)) in other words, if challengeResponse != H(H(encryption key 0)).
// opening is H(encryption key).
func (sender *Sender) Round5Verify(challengeResponses []OtChallengeResponse) ([]ChallengeOpening, error) {
	opening := make([]ChallengeOpening, sender.BatchSize)
	for i := 0; i < sender.BatchSize; i++ {
		for k := 0; k < KeyCount; k++ {
			opening[i][k] = sha3.Sum256(sender.Output.OneTimePadEncryptionKeys[i][k][:])
		}

		// Verify
		hashedKey0 := sha3.Sum256(opening[i][0][:])
		if subtle.ConstantTimeCompare(hashedKey0[:], challengeResponses[i][:]) != 1 {
			return nil, errs.NewVerificationFailed("receiver's challenge response didn't match H(H(rho^0))")
		}
	}
	return opening, nil
}

// Round6Verify is the _last_ part of the "Verification" phase of OT; see p. 16 of https://eprint.iacr.org/2018/499.pdf.
// See step 8 of page 16 of the paper.
// Abort if H(Rho^w) != the one it calculated itself or
//
//	if Xi != H(H(Rho^0)) XOR H(H(Rho^1))
//
// In other words,
//
//	if opening_w != H(decryption key)  or
//	if challenge != H(opening 0) XOR H(opening 0)
func (receiver *Receiver) Round6Verify(challengeOpenings []ChallengeOpening) error {
	for i := 0; i < receiver.BatchSize; i++ {
		hashedDecryptionKey := sha3.Sum256(receiver.Output.OneTimePadDecryptionKey[i][:])
		w := receiver.Output.RandomChoiceBits[i]
		if subtle.ConstantTimeCompare(hashedDecryptionKey[:], challengeOpenings[i][w][:]) != 1 {
			return errs.NewVerificationFailed("sender's supposed H(rho^omega) doesn't match our own")
		}
		hashedKey0 := sha3.Sum256(challengeOpenings[i][0][:])
		hashedKey1 := sha3.Sum256(challengeOpenings[i][1][:])
		reconstructedChallenge, err := bitstring.XorBytes(hashedKey0[:], hashedKey1[:])
		if err != nil {
			return errs.WrapFailed(err, "could not xor bytes")
		}
		if subtle.ConstantTimeCompare(reconstructedChallenge, receiver.SenderChallenge[i][:]) != 1 {
			return errs.NewVerificationFailed("sender's openings H(rho^0) and H(rho^1) didn't decommit to its prior message")
		}
	}
	return nil
}

// Round7Encrypt wraps an `Encrypt` operation on the Sender's underlying output from the random OT; see `Encrypt` below.
// this is optional; it will be used only in circumstances when you want to run "actual" (i.e., non-random) OT.
func (sender *Sender) Round7Encrypt(messages [][KeyCount][DigestSize]byte) ([][KeyCount][DigestSize]byte, error) {
	return sender.Output.Encrypt(messages)
}

// Round8Decrypt wraps a `Decrypt` operation on the Receiver's underlying output from the random OT; see `Decrypt` below
// this is optional; it will be used only in circumstances when you want to run "actual" (i.e., non-random) OT.
func (receiver *Receiver) Round8Decrypt(ciphertext [][KeyCount][DigestSize]byte) ([][DigestSize]byte, error) {
	return receiver.Output.Decrypt(ciphertext)
}

// Encrypt runs step 9) of the seed OT Protocol 7) of https://eprint.iacr.org/2018/499.pdf,
// in which the seed OT sender "encrypts" both messages under the "one-time keys" output by the random OT.
func (s *SenderOutput) Encrypt(plaintexts [][KeyCount][DigestSize]byte) ([][KeyCount][DigestSize]byte, error) {
	batchSize := len(s.OneTimePadEncryptionKeys)
	if len(plaintexts) != batchSize {
		return nil, errs.NewInvalidArgument("message size should be same as batch size")
	}
	ciphertexts := make([][KeyCount][DigestSize]byte, batchSize)

	for i := 0; i < len(plaintexts); i++ {
		for k := 0; k < KeyCount; k++ {
			current, err := bitstring.XorBytes(s.OneTimePadEncryptionKeys[i][k][:], plaintexts[i][k][:])
			if err != nil {
				return nil, errs.WrapFailed(err, "could not xor bytes")
			}
			copy(ciphertexts[i][k][:], current)
		}
	}
	return ciphertexts, nil
}

// Decrypt is step 10) of the seed OT Protocol 7) of https://eprint.iacr.org/2018/499.pdf,
// where the seed OT receiver "decrypts" the message it's receiving using the "key" it received in the random OT.
func (r *ReceiverOutput) Decrypt(ciphertexts [][KeyCount][DigestSize]byte) ([][DigestSize]byte, error) {
	batchSize := len(r.OneTimePadDecryptionKey)
	if len(ciphertexts) != batchSize {
		return nil, errs.NewInvalidArgument("number of ciphertexts should be same as batch size")
	}
	plaintexts := make([][DigestSize]byte, batchSize)

	for i := 0; i < len(ciphertexts); i++ {
		choice := r.RandomChoiceBits[i]
		current, err := bitstring.XorBytes(r.OneTimePadDecryptionKey[i][:], ciphertexts[i][choice][:])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not xor bytes")
		}
		copy(plaintexts[i][:], current)
	}
	return plaintexts, nil
}
