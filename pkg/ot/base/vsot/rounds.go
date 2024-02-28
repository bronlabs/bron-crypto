package vsot

import (
	crand "crypto/rand"
	"crypto/subtle"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
)

const transcriptLabel = "COPPER_KRYPTON_VSOT-"

// The following aliases are not directly used within the round methods. They are helpful for composition.
type Round1P2P struct {
	Proof     compiler.NIZKPoKProof
	PublicKey curves.Point

	_ ds.Incomparable
}
type (
	Round2P2P = [][]ot.ChoiceBits
	Round3P2P = []ot.Message
	Round4P2P = []ot.Message
	Round5P2P = []ot.MessagePair
)

// Round1 computes a secret/public key pair and the dlog proof of the secret key.
func (s *Sender) Round1() (r1out *Round1P2P, err error) {
	// steps 1.1 & 1.2: Sample secret key and compute public key.
	s.SecretKey, err = s.Curve.ScalarField().Random(crand.Reader)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "generating random scalar")
	}
	s.PublicKey = s.Curve.ScalarBaseMult(s.SecretKey)

	// step 1.3: Generate the ZKP proof.
	s.Transcript.AppendMessages("dlog proof", s.SessionId)
	prover, err := s.dlog.NewProver(s.SessionId, s.Transcript.Clone())
	if err != nil {
		return nil, errs.WrapFailed(err, "constructing dlog prover")
	}
	proof, err := prover.Prove(s.PublicKey, s.SecretKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating zkp proof for secret key in base OT sender round 1")
	}
	return &Round1P2P{
		Proof:     proof,
		PublicKey: s.PublicKey,
	}, nil
}

// Round2 verifies the dlog proof of the public key sent by the sender, i.e., step 2),
// and then does receiver's "Pad Transfer" phase in OT, i.e., step 3), of Name 7 (page 16) of the paper.
func (r *Receiver) Round2(r1out *Round1P2P) (r2out Round2P2P, err error) {
	r.SenderPublicKey = r1out.PublicKey
	r.Transcript.AppendMessages("dlog proof", r.SessionId)
	// step 2.1: Verify the dlog proof.
	dlogVerifier, err := r.dlog.NewVerifier(r.SessionId, r.Transcript.Clone())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct dlog verifier")
	}
	if err := dlogVerifier.Verify(r1out.PublicKey, r1out.Proof); err != nil {
		return nil, errs.WrapVerification(err, "verifying dlog proof in base OT receiver round 2")
	}

	r2out = make([][]ot.ChoiceBits, r.Xi)
	r.Output.ChosenMessages = make([]ot.ChosenMessage, r.Xi)
	for i := 0; i < r.Xi; i++ {
		r2out[i] = make([]ot.ChoiceBits, r.L)
		r.Output.ChosenMessages[i] = make([]ot.MessageElement, r.L)
		for l := 0; l < r.L; l++ {
			// step 2.3: Sample random scalar a.
			a, err := r.Curve.ScalarField().Random(crand.Reader)
			if err != nil {
				return nil, errs.WrapRandomSample(err, "generating random scalar")
			}
			// step 2.5: Compute `A := a . G + w . B` in constant time.
			option0 := r.Curve.ScalarBaseMult(a)
			option0Bytes := option0.ToAffineCompressed()
			option1 := option0.Add(r.SenderPublicKey)
			option1Bytes := option1.ToAffineCompressed()

			r2out[i][l] = option0Bytes
			subtle.ConstantTimeCopy(int(r.Output.Choices.Select(i)), r2out[i][l], option1Bytes)
			// step 2.4: Compute m_b
			m_b := r.SenderPublicKey.Mul(a)
			output, err := hashing.HashChain(ot.HashFunction, r.SessionId, []byte{byte(i*r.L + l)}, m_b.ToAffineCompressed())
			if err != nil {
				return nil, errs.WrapHashing(err, "creating one time pad decryption keys")
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
		return nil, errs.NewLength("number of masked choices should be Xi (%d != %d)", len(maskedChoices), s.Xi)
	}
	challenge = make(Round3P2P, s.Xi)
	s.Output.Messages = make([]ot.MessagePair, s.Xi)

	var m [2]curves.Point
	var hashedKey [2][ot.KappaBytes]byte
	negSenderPublicKey := s.PublicKey.Neg()

	for i := 0; i < s.Xi; i++ {
		if len(maskedChoices[i]) != s.L {
			return nil, errs.NewLength("maskedChoices[%d] length should be L (%d != %d)", i, len(maskedChoices[i]), s.L)
		}
		challenge[i] = make(ot.Message, s.L)
		s.Output.Messages[i] = ot.MessagePair{make([]ot.MessageElement, s.L), make([]ot.MessageElement, s.L)}
		for l := 0; l < s.L; l++ {
			// step 3.2: Compute ROT outputs m_0 and m_1
			receiversMaskedChoice, err := s.Curve.Point().FromAffineCompressed(maskedChoices[i][l])
			if err != nil {
				return nil, errs.WrapSerialisation(err, "uncompress the point")
			}
			m[0] = receiversMaskedChoice.Mul(s.SecretKey)
			receiverChoiceMinusSenderPublicKey := receiversMaskedChoice.Add(negSenderPublicKey)
			m[1] = receiverChoiceMinusSenderPublicKey.Mul(s.SecretKey)

			for k := 0; k < 2; k++ {
				output, err := hashing.HashChain(ot.HashFunction, s.SessionId, []byte{byte(i*s.L + l)}, m[k].ToAffineCompressed())
				if err != nil {
					return nil, errs.WrapHashing(err, "creating one time pad encryption keys")
				}
				copy(s.Output.Messages[i][k][l][:], output)

				// step 3.3: Compute challenge by XORing the hash of the hash of the key. Not a typo ;)
				digest, err := hashing.Hash(ot.HashFunction, s.Output.Messages[i][k][l][:])
				if err != nil {
					return nil, errs.WrapHashing(err, "hashing the key (I)")
				}
				digest, err = hashing.Hash(ot.HashFunction, digest)
				if err != nil {
					return nil, errs.WrapHashing(err, "hashing the key (II)")
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
		return nil, errs.NewLength("number of challenges should be Xi (%d != %d)", len(challenge), r.Xi)
	}
	r.SenderChallenge = challenge
	challengeResponses := make(Round4P2P, r.Xi)
	alternativeChallengeResponse := new([ot.KappaBytes]byte)
	// step 4.1: Compute challenge response
	for i := 0; i < r.Xi; i++ {
		if len(challenge[i]) != r.L {
			return nil, errs.NewLength("challenge[%d] length should be L (%d != %d)", i, len(challenge[i]), r.L)
		}
		challengeResponses[i] = make(ot.Message, r.L)
		for l := 0; l < r.L; l++ {
			hashedKey, err := hashing.Hash(ot.HashFunction, r.Output.ChosenMessages[i][l][:])
			if err != nil {
				return nil, errs.WrapHashing(err, "hashing the key (I)")
			}
			hashedKey, err = hashing.Hash(ot.HashFunction, hashedKey)
			if err != nil {
				return nil, errs.WrapHashing(err, "hashing the key (II)")
			}
			challengeResponses[i][l] = [ot.KappaBytes]byte(hashedKey[:ot.KappaBytes])
			subtle.XORBytes(alternativeChallengeResponse[:], r.SenderChallenge[i][l][:], challengeResponses[i][l][:])
			subtle.ConstantTimeCopy(int(r.Output.Choices.Select(i)), challengeResponses[i][l][:], alternativeChallengeResponse[:])
		}
	}
	return challengeResponses, nil
}

// Round5 verifies the challenge response. If the verification passes, sender
// opens his challenges to the receiver. See step 7 of page 16 of the paper.
func (s *Sender) Round5(challengeResponses Round4P2P) (Round5P2P, error) {
	if len(challengeResponses) != s.Xi {
		return nil, errs.NewLength("number of challenge responses should be Xi (%d != %d)", len(challengeResponses), s.Xi)
	}
	opening := make(Round5P2P, s.Xi)
	for i := 0; i < s.Xi; i++ {
		if len(challengeResponses[i]) != s.L {
			return nil, errs.NewLength("challengeResponses[%d] length should be L (%d != %d)", i, len(challengeResponses[i]), s.L)
		}
		opening[i] = ot.MessagePair{make([]ot.MessageElement, s.L), make([]ot.MessageElement, s.L)}
		for l := 0; l < s.L; l++ {
			for k := 0; k < 2; k++ {
				digest, err := hashing.Hash(ot.HashFunction, s.Output.Messages[i][k][l][:])
				if err != nil {
					return nil, errs.WrapHashing(err, "hashing the messages")
				}
				opening[i][k][l] = [ot.KappaBytes]byte(digest[:ot.KappaBytes])
			}

			// step 5.1: Verify the challenge response
			hashedKey0, err := hashing.Hash(ot.HashFunction, opening[i][0][l][:])
			if err != nil {
				return nil, errs.WrapHashing(err, "hashing the key to verify the challenge response")
			}
			if subtle.ConstantTimeCompare(hashedKey0, challengeResponses[i][l][:]) != 1 {
				return nil, errs.NewTotalAbort("VSOT Receiver", "receiver's challenge response didn't match H(H(m^0))")
			}
		}
	}
	return opening, nil
}

// Round6 is the _last_ part of the "Verification" phase of OT;
// See step 8 of page 16 of the paper.
func (r *Receiver) Round6(challengeOpenings Round5P2P) error {
	if len(challengeOpenings) != r.Xi {
		return errs.NewLength("number of challenge openings should be Xi (%d != %d)", len(challengeOpenings), r.Xi)
	}
	var reconstructedChallenge [ot.KappaBytes]byte
	for i := 0; i < r.Xi; i++ {
		if len(challengeOpenings[i][0]) != r.L || len(challengeOpenings[i][1]) != r.L {
			return errs.NewLength("challengeOpenings[%d] length should be L (%d != %d || %d != %d )",
				i, len(challengeOpenings[i][0]), r.L, len(challengeOpenings[i][1]), r.L)
		}
		for l := 0; l < r.L; l++ {
			// step 6.1: Verify the challenge openings
			hashedDecryptionKey, err := hashing.Hash(ot.HashFunction, r.Output.ChosenMessages[i][l][:])
			if err != nil {
				return errs.WrapHashing(err, "hashing the decryption key to open challenge")
			}
			choice := r.Output.Choices.Select(i)
			if subtle.ConstantTimeCompare(hashedDecryptionKey, challengeOpenings[i][choice][l][:]) != 1 {
				return errs.NewTotalAbort("VSOT sender", "sender's supposed H(m^omega) doesn't match our own")
			}
			// step 6.2: Reconstruct the challenge and verify it
			hashedKey0, err := hashing.Hash(ot.HashFunction, challengeOpenings[i][0][l][:])
			if err != nil {
				return errs.WrapHashing(err, "hashing the key0 to verify the challenge response")
			}
			hashedKey1, err := hashing.Hash(ot.HashFunction, challengeOpenings[i][1][l][:])
			if err != nil {
				return errs.WrapHashing(err, "hashing the key1 to verify the challenge response")
			}
			subtle.XORBytes(reconstructedChallenge[:], hashedKey0, hashedKey1)

			if subtle.ConstantTimeCompare(reconstructedChallenge[:], r.SenderChallenge[i][l][:]) != 1 {
				return errs.NewTotalAbort("VSOT sender", "sender's openings H(m^0) and H(m^1) didn't decommit to its prior message")
			}
		}
	}
	return nil
}
