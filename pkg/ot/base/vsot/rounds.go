package vsot

import (
	crand "crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	dlog "github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/fischlin"
)

const label = "KRYPTON_PRIMITIVES_BASE_OT_SIMPLEST"

// The following aliases are not directly used within the round methods. They are helpful for composition.
type Round1P2P struct {
	Proof     *dlog.Proof
	PublicKey curves.Point

	_ types.Incomparable
}
type (
	Round2P2P = [][]ot.ChoiceBits
	Round3P2P = []ot.Message
	Round4P2P = []ot.Message
	Round5P2P = []ot.MessagePair
)

// Round1 computes a secret/public key pair and the dlog proof of the secret key.
func (s *Sender) Round1() (r1out *Round1P2P, err error) {
	// Sample the secret key and compute the public key.
	s.SecretKey, err = s.Curve.ScalarField().Random(crand.Reader)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "generating random scalar")
	}
	s.PublicKey = s.Curve.ScalarBaseMult(s.SecretKey)

	// Generate the ZKP proof.
	s.Transcript.AppendMessages("dlog proof", s.UniqueSessionId)
	prover, err := dlog.NewProver(s.Curve.Generator(), s.UniqueSessionId, s.Transcript.Clone(), s.Csprng)
	if err != nil {
		return nil, errs.WrapFailed(err, "constructing dlog prover")
	}
	proof, publicKey, err := prover.Prove(s.SecretKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating zkp proof for secret key in base OT sender round 1")
	}
	return &Round1P2P{
		Proof:     proof,
		PublicKey: publicKey,
	}, nil
}

// Round2 verifies the dlog proof of the public key sent by the sender, i.e., step 2),
// and then does receiver's "Pad Transfer" phase in OT, i.e., step 3), of Name 7 (page 16) of the paper.
func (r *Receiver) Round2(r1out *Round1P2P) (r2out Round2P2P, err error) {
	r.SenderPublicKey = r1out.PublicKey
	r.Transcript.AppendMessages("dlog proof", r.UniqueSessionId)
	if err := dlog.Verify(r.Curve.Generator(), r1out.PublicKey, r1out.Proof, r.UniqueSessionId); err != nil {
		return nil, errs.WrapVerificationFailed(err, "verifying dlog proof in base OT receiver round 2")
	}

	r2out = make([][]ot.ChoiceBits, r.Xi)
	r.Output.ChosenMessages = make([]ot.ChosenMessage, r.Xi)
	for i := 0; i < r.Xi; i++ {
		r2out[i] = make([]ot.ChoiceBits, r.L)
		r.Output.ChosenMessages[i] = make([]ot.MessageElement, r.L)
		for l := 0; l < r.L; l++ {
			a, err := r.Curve.ScalarField().Random(crand.Reader)
			if err != nil {
				return nil, errs.WrapRandomSampleFailed(err, "generating random scalar")
			}
			// Computing `A := a . G + w . B` in constant time, by first computing option0 = a.G and option1 = a.G+B and then
			// constant time choosing one of them by first assuming that the output is option0, and overwrite it if the choice bit is 1.

			option0 := r.Curve.ScalarBaseMult(a)
			option0Bytes := option0.ToAffineCompressed()
			option1 := option0.Add(r.SenderPublicKey)
			option1Bytes := option1.ToAffineCompressed()

			r2out[i][l] = option0Bytes
			subtle.ConstantTimeCopy(int(r.Output.Choices.Select(i)), r2out[i][l], option1Bytes)
			// compute the internal rho
			rho := r.SenderPublicKey.Mul(a)
			output, err := hashing.HashChain(sha3.New256, r.UniqueSessionId, []byte{byte(i*r.L + l)}, rho.ToAffineCompressed())
			if err != nil {
				return nil, errs.WrapFailed(err, "creating one time pad decryption keys")
			}
			copy(r.Output.ChosenMessages[i][l][:], output)
		}
	}
	return r2out, nil
}

// Round3 is the sender's "Pad Transfer" phase in OT; see steps 4 and 5 of page 16 of the paper.
// Returns the challenges xi.
func (s *Sender) Round3(maskedChoices Round2P2P) (challenge Round3P2P, err error) {
	if len(maskedChoices) != s.Xi {
		return nil, errs.NewInvalidLength("number of masked choices should be Xi (%d != %d)", len(maskedChoices), s.Xi)
	}
	challenge = make(Round3P2P, s.Xi)
	s.Output.Messages = make([]ot.MessagePair, s.Xi)

	var rho [2]curves.Point
	var hashedKey [2][ot.KappaBytes]byte
	negSenderPublicKey := s.PublicKey.Neg()

	for i := 0; i < s.Xi; i++ {
		if len(maskedChoices[i]) != s.L {
			return nil, errs.NewInvalidLength("maskedChoices[%d] length should be L (%d != %d)", i, len(maskedChoices[i]), s.L)
		}
		challenge[i] = make(ot.Message, s.L)
		s.Output.Messages[i] = ot.MessagePair{make([]ot.MessageElement, s.L), make([]ot.MessageElement, s.L)}
		for l := 0; l < s.L; l++ {
			receiversMaskedChoice, err := s.Curve.Point().FromAffineCompressed(maskedChoices[i][l])
			if err != nil {
				return nil, errs.WrapSerialisation(err, "uncompress the point")
			}

			// Sender creates two options that will eventually be used as her encryption keys.
			rho[0] = receiversMaskedChoice.Mul(s.SecretKey)

			receiverChoiceMinusSenderPublicKey := receiversMaskedChoice.Add(negSenderPublicKey)
			rho[1] = receiverChoiceMinusSenderPublicKey.Mul(s.SecretKey)

			for k := 0; k < 2; k++ {
				output, err := hashing.HashChain(ot.HashFunction, s.UniqueSessionId, []byte{byte(i*s.L + l)}, rho[k].ToAffineCompressed())
				if err != nil {
					return nil, errs.WrapFailed(err, "creating one time pad encryption keys")
				}
				copy(s.Output.Messages[i][k][l][:], output)

				// Compute a challenge by XORing the hash of the hash of the key. Not a typo ;)
				digest, err := hashing.Hash(ot.HashFunction, s.Output.Messages[i][k][l][:])
				if err != nil {
					return nil, errs.WrapHashingFailed(err, "hashing the key (I)")
				}
				digest, err = hashing.Hash(ot.HashFunction, digest)
				if err != nil {
					return nil, errs.WrapHashingFailed(err, "hashing the key (II)")
				}
				hashedKey[k] = [ot.KappaBytes]byte(digest[:ot.KappaBytes])
			}
			subtle.XORBytes(challenge[i][l][:], hashedKey[0][:], hashedKey[1][:])
		}
	}
	return challenge, nil
}

// Round4 corresponds to initial round of the receiver's "Verify" phase; see step 6 of page 16 of the paper.
// this is just the start of Verification. In this round, the receiver outputs "rho'", which the sender will check.
func (r *Receiver) Round4(challenge Round3P2P) (Round4P2P, error) {
	if len(challenge) != r.Xi {
		return nil, errs.NewInvalidLength("number of challenges should be Xi (%d != %d)", len(challenge), r.Xi)
	}
	// store to be used in future steps
	r.SenderChallenge = challenge
	// challengeResponses is Rho' in the paper.
	challengeResponses := make(Round4P2P, r.Xi)
	alternativeChallengeResponse := new([ot.KappaBytes]byte)
	for i := 0; i < r.Xi; i++ {
		if len(challenge[i]) != r.L {
			return nil, errs.NewInvalidLength("challenge[%d] length should be L (%d != %d)", i, len(challenge[i]), r.L)
		}
		challengeResponses[i] = make(ot.Message, r.L)
		for l := 0; l < r.L; l++ {
			// Constant-time xor of the hashed key and the challenge, based on the choice bit.
			hashedKey, err := hashing.Hash(ot.HashFunction, r.Output.ChosenMessages[i][l][:])
			if err != nil {
				return nil, errs.WrapHashingFailed(err, "hashing the key (I)")
			}
			hashedKey, err = hashing.Hash(ot.HashFunction, hashedKey)
			if err != nil {
				return nil, errs.WrapHashingFailed(err, "hashing the key (II)")
			}
			challengeResponses[i][l] = [ot.KappaBytes]byte(hashedKey[:ot.KappaBytes])
			subtle.XORBytes(alternativeChallengeResponse[:], r.SenderChallenge[i][l][:], challengeResponses[i][l][:])
			subtle.ConstantTimeCopy(int(r.Output.Choices.Select(i)), challengeResponses[i][l][:], alternativeChallengeResponse[:])
		}
	}
	return challengeResponses, nil
}

// Round5 verifies the challenge response. If the verification passes, sender opens his challenges to the receiver.
// See step 7 of page 16 of the paper.
// Abort if Rho' != H(H(Rho^0)) in other words, if challengeResponse != H(H(encryption key 0)).
// opening is H(encryption key).
func (s *Sender) Round5(challengeResponses Round4P2P) (Round5P2P, error) {
	if len(challengeResponses) != s.Xi {
		return nil, errs.NewInvalidLength("number of challenge responses should be Xi (%d != %d)", len(challengeResponses), s.Xi)
	}
	opening := make(Round5P2P, s.Xi)
	for i := 0; i < s.Xi; i++ {
		if len(challengeResponses[i]) != s.L {
			return nil, errs.NewInvalidLength("challengeResponses[%d] length should be L (%d != %d)", i, len(challengeResponses[i]), s.L)
		}
		opening[i] = ot.MessagePair{make([]ot.MessageElement, s.L), make([]ot.MessageElement, s.L)}
		for l := 0; l < s.L; l++ {
			for k := 0; k < 2; k++ {
				digest, err := hashing.Hash(ot.HashFunction, s.Output.Messages[i][k][l][:])
				if err != nil {
					return nil, errs.WrapHashingFailed(err, "hashing the messages")
				}
				opening[i][k][l] = [ot.KappaBytes]byte(digest[:ot.KappaBytes])
			}

			// Verify
			hashedKey0 := sha3.Sum256(opening[i][0][l][:])
			if subtle.ConstantTimeCompare(hashedKey0[:], challengeResponses[i][l][:]) != 1 {
				return nil, errs.NewVerificationFailed("receiver's challenge response didn't match H(H(rho^0))")
			}
		}
	}
	return opening, nil
}

// Round6 is the _last_ part of the "Verification" phase of OT; see p. 16 of https://eprint.iacr.org/2018/499.pdf.
// See step 8 of page 16 of the paper.
// Abort if H(Rho^w) != the one it calculated itself or
//
//	if Xi != H(H(Rho^0)) XOR H(H(Rho^1))
//
// In other words,
//
//	if opening_w != H(decryption key)  or
//	if challenge != H(opening 0) XOR H(opening 0)
func (r *Receiver) Round6(challengeOpenings Round5P2P) error {
	if len(challengeOpenings) != r.Xi {
		return errs.NewInvalidLength("number of challenge openings should be Xi (%d != %d)", len(challengeOpenings), r.Xi)
	}
	var reconstructedChallenge [ot.KappaBytes]byte
	for i := 0; i < r.Xi; i++ {
		if len(challengeOpenings[i][0]) != r.L || len(challengeOpenings[i][1]) != r.L {
			return errs.NewInvalidLength("challengeOpenings[%d] length should be L (%d != %d || %d != %d )",
				i, len(challengeOpenings[i][0]), r.L, len(challengeOpenings[i][1]), r.L)
		}
		for l := 0; l < r.L; l++ {
			hashedDecryptionKey := sha3.Sum256(r.Output.ChosenMessages[i][l][:])
			choice := r.Output.Choices.Select(i)
			if subtle.ConstantTimeCompare(hashedDecryptionKey[:], challengeOpenings[i][choice][l][:]) != 1 {
				return errs.NewVerificationFailed("sender's supposed H(rho^omega) doesn't match our own")
			}
			hashedKey0 := sha3.Sum256(challengeOpenings[i][0][l][:])
			hashedKey1 := sha3.Sum256(challengeOpenings[i][1][l][:])
			subtle.XORBytes(reconstructedChallenge[:], hashedKey0[:], hashedKey1[:])

			if subtle.ConstantTimeCompare(reconstructedChallenge[:], r.SenderChallenge[i][l][:]) != 1 {
				return errs.NewVerificationFailed("sender's openings H(rho^0) and H(rho^1) didn't decommit to its prior message")
			}
		}
	}
	return nil
}
