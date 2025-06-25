package ecbbot

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

const (
	TaggedKeyAgreementMs = "BRON_CRYPTO-BBOT-KA-MA-"
	PopfKeyLabel         = "BRON_CRYPTO-BBOT-POPF-"
	Ro0Label             = "BRON_CRYPTO-BBOT-RO0-"
	Ro1Label             = "BRON_CRYPTO-BBOT-RO1-"
	TagLength            = ot.KappaBytes
)

func (s *Sender) Round1() (r1out *Round1P2P, err error) {
	// Validation
	if s.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, s.Round)
	}

	// step 1.1 (KA.R)
	s.State.A, err = s.ka.R(s.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "generating a")
	}

	// step 1.2 (KA.msg_1)
	mS, err := s.ka.Msg1(s.State.A)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "creating msg1")
	}

	// step 1.3 (Setup RO)
	s.Transcript.AppendPoints(TaggedKeyAgreementMs, mS)

	s.Round = 3
	r1out = &Round1P2P{
		MS: mS,
	}
	return r1out, nil
}

func (r *Receiver) Round2(r1out *Round1P2P, choices ot.PackedBits) (r2out *Round2P2P, receiverOut *ReceiverOutput, err error) {
	// Validation
	if r.Round != 2 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 2, r.Round)
	}
	if err := r1out.Validate(r.Protocol); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round %d input", r.Round)
	}

	// Setup ROs
	r.Transcript.AppendPoints(TaggedKeyAgreementMs, r1out.MS)
	popf, err := r.makeProgrammableOncePublicFunction()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "creating popf")
	}

	// step 2.1
	phi := make([][2][]curves.Point, r.Protocol.Xi)
	receiverOut = NewReceiverOutput(r.Protocol.Xi, r.Protocol.L)
	receiverOut.Choices = choices
	for i := 0; i < r.Protocol.Xi; i++ {
		ci := choices.Get(uint(i))
		phi[i] = [2][]curves.Point{make([]curves.Point, r.Protocol.L), make([]curves.Point, r.Protocol.L)}
		for l := 0; l < r.Protocol.L; l++ {
			// step 2.2 (KA.R)
			bi, err := r.ka.R(r.Prng)
			if err != nil {
				return nil, nil, errs.WrapRandomSample(err, "generating random scalar bi")
			}

			// step 2.3 (KA.msg_2)
			mRi, err := r.ka.Msg2(bi, r1out.MS)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "creating msg2")
			}

			// step 2.4 (KA.key_2)
			tag := r.makeKeyAgreementTag(i, l, ci)
			receiverOut.R[i][l], err = r.ka.Key2(bi, r1out.MS, tag)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "computing shared bytes for KA.key_2")
			}

			// step 2.5,2.6 (POPF.Program)
			phi[i][0][l], phi[i][1][l], err = popf.Program(ci, mRi, r.Prng)
			if err != nil {
				return nil, nil, errs.WrapRandomSample(err, "generating random scalar sc")
			}
		}
	}

	r.Round++
	r2out = &Round2P2P{Phi: phi}
	return r2out, receiverOut, nil
}

func (s *Sender) Round3(r2out *Round2P2P) (senderOut *SenderOutput, err error) {
	// Validation
	if s.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, s.Round)
	}
	if err := r2out.Validate(s.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", s.Round)
	}

	popf, err := s.makeProgrammableOncePublicFunction()
	if err != nil {
		return nil, errs.WrapFailed(err, "creating popf")
	}

	// step 3.1
	senderOut = NewSenderOutput(s.Protocol.Xi, s.Protocol.L)
	for i := 0; i < s.Protocol.Xi; i++ {
		for l := 0; l < s.Protocol.L; l++ {
			for j := byte(0); j < 2; j++ {
				// step 3.2 (POPF.Eval)
				p, err := popf.Eval(r2out.Phi[i][0][l], r2out.Phi[i][1][l], j)
				if err != nil {
					return nil, errs.WrapFailed(err, "popf eval")
				}

				// step 3.3 (KA.key_1)
				tag := s.makeKeyAgreementTag(i, l, j)
				senderOut.S[i][j][l], err = s.ka.Key2(s.State.A, p, tag)
				if err != nil {
					return nil, errs.WrapFailed(err, "computing shared bytes for KA.key_2")
				}
			}
		}
	}

	s.Round++
	return senderOut, nil
}

func (p *Participant) makeProgrammableOncePublicFunction() (popf *Popf, err error) {
	var tagsRandomOracle [2][]byte
	tagsRandomOracle[0], err = p.Transcript.ExtractBytes(Ro0Label, TagLength)
	if err != nil {
		return nil, errs.WrapHashing(err, "extracting tag Ro0")
	}
	tagsRandomOracle[1], err = p.Transcript.ExtractBytes(Ro1Label, TagLength)
	if err != nil {
		return nil, errs.WrapHashing(err, "extracting tag Ro1")
	}
	popf, err = NewPopf(tagsRandomOracle[0], tagsRandomOracle[1])
	if err != nil {
		return nil, errs.WrapFailed(err, "creating popf")
	}
	return popf, nil
}

func (p *Participant) makeKeyAgreementTag(chi, l int, j byte) []byte {
	return slices.Concat([]byte(PopfKeyLabel), bitstring.ToBytes32LE(int32(chi*p.Protocol.L+l)), []byte{j})
}
