package vsot

import (
	"crypto/subtle"

	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

const transcriptLabel = "COPPER_KRYPTON_VSOT-"

// Round1 computes a secret/public key pair and the dlog proof of the secret key.
func (s *Sender) Round1() (r1out *Round1P2P, err error) {
	// Validation
	if s.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, s.Round)
	}

	// steps 1.1 & 1.2: Sample secret key and compute public key.
	s.SecretKey, err = s.Protocol.Curve().ScalarField().Random(s.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "generating random scalar")
	}
	s.PublicKey = s.Protocol.Curve().ScalarBaseMult(s.SecretKey)

	// step 1.3: Generate the ZKP proof.
	prover, err := s.dlog.NewProver(s.SessionId, s.Transcript.Clone())
	if err != nil {
		return nil, errs.WrapFailed(err, "constructing dlog prover")
	}
	proof, err := prover.Prove(s.PublicKey, s.SecretKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating zkp proof for secret key in base OT sender round 1")
	}

	s.Round = 3
	return &Round1P2P{
		Proof:     proof,
		PublicKey: s.PublicKey,
	}, nil
}

// Round2 verifies the dlog proof of the public key sent by the sender, i.e., step 2),
// and then does receiver's "Pad Transfer" phase in OT, i.e., step 3), of Name 7 (page 16) of the paper.
func (r *Receiver) Round2(r1out *Round1P2P) (r2out *Round2P2P, err error) {
	// Validation
	if r.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, r.Round)
	}
	if err := r1out.Validate(r.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", r.Round)
	}

	r.SenderPublicKey = r1out.PublicKey

	// step 2.1: Verify the dlog proof.
	dlogVerifier, err := r.dlog.NewVerifier(r.SessionId, r.Transcript.Clone())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct dlog verifier")
	}
	if err := dlogVerifier.Verify(r1out.PublicKey, r1out.Proof); err != nil {
		return nil, errs.WrapVerification(err, "verifying dlog proof in base OT receiver round 2")
	}

	r2out = &Round2P2P{
		MaskedChoices: make([][]ot.PackedBits, r.Protocol.Xi),
	}
	r.Output.ChosenMessages = make([]ot.Message, r.Protocol.Xi)
	for i := 0; i < r.Protocol.Xi; i++ {
		r2out.MaskedChoices[i] = make([]ot.PackedBits, r.Protocol.L)
		r.Output.ChosenMessages[i] = make([]ot.MessageElement, r.Protocol.L)
		for l := 0; l < r.Protocol.L; l++ {
			// step 2.3: Sample random scalar a.
			a, err := r.Protocol.Curve().ScalarField().Random(r.Prng)
			if err != nil {
				return nil, errs.WrapRandomSample(err, "generating random scalar")
			}
			// step 2.5: Compute `A := a . G + w . B` in constant time.
			option0 := r.Protocol.Curve().ScalarBaseMult(a)
			option0Bytes := option0.ToAffineCompressed()
			option1 := option0.Add(r.SenderPublicKey)
			option1Bytes := option1.ToAffineCompressed()

			r2out.MaskedChoices[i][l] = option0Bytes
			subtle.ConstantTimeCopy(int(r.Output.Choices.Get(uint(i))), r2out.MaskedChoices[i][l], option1Bytes)
			// step 2.4: Compute m_b
			m_b := r.SenderPublicKey.ScalarMul(a)
			output, err := hashing.HashChain(ot.HashFunction, r.SessionId, []byte{byte(i*r.Protocol.L + l)}, m_b.ToAffineCompressed())
			if err != nil {
				return nil, errs.WrapHashing(err, "creating one time pad decryption keys")
			}
			copy(r.Output.ChosenMessages[i][l][:], output)
		}
	}
	r.Round = 4
	return r2out, nil
}

// Round3 is the sender's "Pad Transfer" phase in OT; see steps 4 and 5 of page 16 of the paper.
// Returns the challenges xi.
func (s *Sender) Round3(r2out *Round2P2P) (r3out *Round3P2P, err error) {
	// Validation
	if s.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, s.Round)
	}

	if err := r2out.Validate(s.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", s.Round)
	}

	r3out = &Round3P2P{
		Challenge: make([]ot.Message, s.Protocol.Xi),
	}
	s.Output.MessagePairs = make([][2]ot.Message, s.Protocol.Xi)

	var m [2]curves.Point
	var hashedKey [2][ot.KappaBytes]byte
	negSenderPublicKey := s.PublicKey.Neg()
	for i := 0; i < s.Protocol.Xi; i++ {
		r3out.Challenge[i] = make(ot.Message, s.Protocol.L)
		s.Output.MessagePairs[i] = [2]ot.Message{make([]ot.MessageElement, s.Protocol.L), make([]ot.MessageElement, s.Protocol.L)}
		for l := 0; l < s.Protocol.L; l++ {
			// step 3.2: Compute ROT outputs m_0 and m_1
			receiversMaskedChoice, err := s.Protocol.Curve().Point().FromAffineCompressed(r2out.MaskedChoices[i][l])
			if err != nil {
				return nil, errs.WrapSerialisation(err, "uncompress the point")
			}
			m[0] = receiversMaskedChoice.ScalarMul(s.SecretKey)
			receiverChoiceMinusSenderPublicKey := receiversMaskedChoice.Add(negSenderPublicKey)
			m[1] = receiverChoiceMinusSenderPublicKey.ScalarMul(s.SecretKey)

			for k := 0; k < 2; k++ {
				output, err := hashing.HashChain(ot.HashFunction, s.SessionId, []byte{byte(i*s.Protocol.L + l)}, m[k].ToAffineCompressed())
				if err != nil {
					return nil, errs.WrapHashing(err, "creating one time pad encryption keys")
				}
				copy(s.Output.MessagePairs[i][k][l][:], output[:ot.KappaBytes])

				// step 3.3: Compute challenge by XORing the hash of the hash of the key. Not a typo ;)
				digest, err := hashing.Hash(ot.HashFunction, s.Output.MessagePairs[i][k][l][:])
				if err != nil {
					return nil, errs.WrapHashing(err, "hashing the key (I)")
				}
				digest, err = hashing.Hash(ot.HashFunction, digest[:ot.KappaBytes])
				if err != nil {
					return nil, errs.WrapHashing(err, "hashing the key (II)")
				}
				hashedKey[k] = [ot.KappaBytes]byte(digest[:ot.KappaBytes])
			}
			subtle.XORBytes(r3out.Challenge[i][l][:], hashedKey[0][:], hashedKey[1][:])
		}
	}

	s.Round = 5
	return r3out, nil
}

// Round4 corresponds to initial round of the receiver's "Verify" phase; see step 6 of page 16 of the paper.
// this is just the start of Verification. In this round, the receiver outputs "rho'", which the sender will check.
func (r *Receiver) Round4(r3out *Round3P2P) (*Round4P2P, error) {
	// Validation
	if r.Round != 4 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 4, r.Round)
	}

	if err := r3out.Validate(r.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", r.Round)
	}

	r.SenderChallenge = r3out.Challenge
	r4out := &Round4P2P{
		Responses: make([]ot.Message, r.Protocol.Xi),
	}

	// step 4.1: Compute challenge response
	alternativeChallengeResponse := new([ot.KappaBytes]byte)
	for i := 0; i < r.Protocol.Xi; i++ {
		r4out.Responses[i] = make(ot.Message, r.Protocol.L)
		for l := 0; l < r.Protocol.L; l++ {
			hashedKey, err := hashing.Hash(ot.HashFunction, r.Output.ChosenMessages[i][l][:])
			if err != nil {
				return nil, errs.WrapHashing(err, "hashing the key (I)")
			}
			hashedKey, err = hashing.Hash(ot.HashFunction, hashedKey[:ot.KappaBytes])
			if err != nil {
				return nil, errs.WrapHashing(err, "hashing the key (II)")
			}
			r4out.Responses[i][l] = [ot.KappaBytes]byte(hashedKey[:ot.KappaBytes])
			subtle.XORBytes(alternativeChallengeResponse[:], r.SenderChallenge[i][l][:], r4out.Responses[i][l][:])
			subtle.ConstantTimeCopy(int(r.Output.Choices.Get(uint(i))), r4out.Responses[i][l][:], alternativeChallengeResponse[:])
		}
	}

	r.Round = 6
	return r4out, nil
}

// Round5 verifies the challenge response. If the verification passes, sender
// opens his challenges to the receiver. See step 7 of page 16 of the paper.
func (s *Sender) Round5(r4out *Round4P2P) (*Round5P2P, error) {
	// Validation
	if s.Round != 5 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 5, s.Round)
	}

	if err := r4out.Validate(s.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", s.Round)
	}

	r5out := &Round5P2P{
		Openings: make([][2]ot.Message, s.Protocol.Xi),
	}
	for i := 0; i < s.Protocol.Xi; i++ {
		r5out.Openings[i] = [2]ot.Message{make([]ot.MessageElement, s.Protocol.L), make([]ot.MessageElement, s.Protocol.L)}
		for l := 0; l < s.Protocol.L; l++ {
			for k := 0; k < 2; k++ {
				digest, err := hashing.Hash(ot.HashFunction, s.Output.MessagePairs[i][k][l][:])
				if err != nil {
					return nil, errs.WrapHashing(err, "hashing the messages")
				}
				r5out.Openings[i][k][l] = [ot.KappaBytes]byte(digest[:ot.KappaBytes])
			}

			// step 5.1: Verify the challenge response
			hashedKey0, err := hashing.Hash(ot.HashFunction, r5out.Openings[i][0][l][:])
			if err != nil {
				return nil, errs.WrapHashing(err, "hashing the key to verify the challenge response")
			}
			if subtle.ConstantTimeCompare(hashedKey0[:ot.KappaBytes], r4out.Responses[i][l][:]) != 1 {
				return nil, errs.NewIdentifiableAbort(s.OtherParty().String(), "receiver's challenge response didn't match H(H(m^0))")
			}
		}
	}

	s.Round++
	return r5out, nil
}

// Round6 is the _last_ part of the "Verification" phase of OT;
// See step 8 of page 16 of the paper.
func (r *Receiver) Round6(r5out *Round5P2P) error {
	// Validation
	if r.Round != 6 {
		return errs.NewRound("Running round %d but participant expected round %d", 6, r.Round)
	}
	if err := r5out.Validate(r.Protocol); err != nil {
		return errs.WrapValidation(err, "invalid round %d input", r.Round)
	}

	var reconstructedChallenge, challengeOpening [ot.KappaBytes]byte
	for i := 0; i < r.Protocol.Xi; i++ {
		for l := 0; l < r.Protocol.L; l++ {
			// step 6.1: Verify the challenge openings
			hashedDecryptionKey, err := hashing.Hash(ot.HashFunction, r.Output.ChosenMessages[i][l][:])
			if err != nil {
				return errs.WrapHashing(err, "hashing the decryption key to open challenge")
			}
			choice := int(r.Output.Choices.Get(uint(i)))
			ct.SelectSlice(choice, challengeOpening[:], r5out.Openings[i][0][l][:], r5out.Openings[i][1][l][:])
			if subtle.ConstantTimeCompare(hashedDecryptionKey[:ot.KappaBytes], challengeOpening[:]) != 1 {
				return errs.NewIdentifiableAbort(r.OtherParty().String(), "sender's supposed H(m^omega) doesn't match our own")
			}
			// step 6.2: Reconstruct the challenge and verify it
			hashedKey0, err := hashing.Hash(ot.HashFunction, r5out.Openings[i][0][l][:])
			if err != nil {
				return errs.WrapHashing(err, "hashing the key0 to verify the challenge response")
			}
			hashedKey1, err := hashing.Hash(ot.HashFunction, r5out.Openings[i][1][l][:])
			if err != nil {
				return errs.WrapHashing(err, "hashing the key1 to verify the challenge response")
			}
			subtle.XORBytes(reconstructedChallenge[:], hashedKey0[:ot.KappaBytes], hashedKey1[:ot.KappaBytes])

			if subtle.ConstantTimeCompare(reconstructedChallenge[:], r.SenderChallenge[i][l][:]) != 1 {
				return errs.NewIdentifiableAbort(r.OtherParty().String(), "sender's openings H(m^0) and H(m^1) didn't decommit to its prior message")
			}
		}
	}

	r.Round++
	return nil
}
