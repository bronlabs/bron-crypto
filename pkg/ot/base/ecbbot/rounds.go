package ecbbot

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

const (
	TaggedKeyAgreementMs = "BRON_CRYPTO-BBOT-KA-MA-"
	PopfKeyLabel         = "BRON_CRYPTO-BBOT-POPF-"
	Ro0Label             = "BRON_CRYPTO-BBOT-RO0-"
	Ro1Label             = "BRON_CRYPTO-BBOT-RO1-"
	TagLength            = 16
)

func (s *Sender[GE, SE]) Round1() (r1out *Round1P2P[GE, SE], err error) {
	// Validation
	if s.round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, s.round)
	}

	// step 1.1 (KA.R)
	s.State.A, err = s.ka.R(s.prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "generating a")
	}

	// step 1.2 (KA.msg_1)
	ms, err := s.ka.Msg1(s.State.A)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "creating msg1")
	}

	// step 1.3 (Setup RO)
	s.tape.AppendBytes(TaggedKeyAgreementMs, ms.Bytes())

	s.round = 3
	r1out = &Round1P2P[GE, SE]{
		MS: ms,
	}
	return r1out, nil
}

func (r *Receiver[GE, SE]) Round2(r1out *Round1P2P[GE, SE], choices []byte) (r2out *Round2P2P[GE, SE], receiverOut *ReceiverOutput[SE], err error) {
	// Validation
	if r.round != 2 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 2, r.round)
	}
	//if err := r1out.Validate(r.Protocol); err != nil {
	//	return nil, nil, errs.WrapValidation(err, "invalid round %d input", r.Round)
	//}

	// Setup ROs
	r.tape.AppendBytes(TaggedKeyAgreementMs, r1out.MS.Bytes())
	f, err := r.makeProgrammableOncePublicFunction()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "creating popf")
	}

	// step 2.1
	phi := make([][2][]GE, r.chi)
	receiverOut = NewReceiverOutput[SE](r.chi, r.l)
	receiverOut.Choices = choices
	for i := 0; i < r.chi; i++ {
		ci := (choices[i/8] >> (i % 8)) & 0b1
		phi[i] = [2][]GE{make([]GE, r.l), make([]GE, r.l)}
		for l := 0; l < r.l; l++ {
			// step 2.2 (KA.R)
			bi, err := r.ka.R(r.prng)
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
			phi[i][0][l], phi[i][1][l], err = f.Program(ci, mRi, r.prng)
			if err != nil {
				return nil, nil, errs.WrapRandomSample(err, "generating random scalar sc")
			}
		}
	}

	r.round++
	r2out = &Round2P2P[GE, SE]{Phi: phi}
	return r2out, receiverOut, nil
}

func (s *Sender[GE, SE]) Round3(r2out *Round2P2P[GE, SE]) (senderOut *SenderOutput[SE], err error) {
	// Validation
	if s.round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, s.round)
	}
	//if err := r2out.Validate(s.Protocol); err != nil {
	//	return nil, errs.WrapValidation(err, "invalid round %d input", s.Round)
	//}

	f, err := s.makeProgrammableOncePublicFunction()
	if err != nil {
		return nil, errs.WrapFailed(err, "creating popf")
	}

	// step 3.1
	senderOut = NewSenderOutput[SE](s.chi, s.l)
	for i := 0; i < s.chi; i++ {
		for l := 0; l < s.l; l++ {
			for j := byte(0); j < 2; j++ {
				// step 3.2 (POPF.Eval)
				p, err := f.Eval(r2out.Phi[i][0][l], r2out.Phi[i][1][l], j)
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

	s.round++
	return senderOut, nil
}

func (p *Participant[GE, SE]) makeProgrammableOncePublicFunction() (f *Popf[GE, SE], err error) {
	var tagsRandomOracle [2][]byte
	tagsRandomOracle[0], err = p.tape.ExtractBytes(Ro0Label, TagLength)
	if err != nil {
		return nil, errs.WrapHashing(err, "extracting tag Ro0")
	}
	tagsRandomOracle[1], err = p.tape.ExtractBytes(Ro1Label, TagLength)
	if err != nil {
		return nil, errs.WrapHashing(err, "extracting tag Ro1")
	}
	f, err = NewPopf(p.group, tagsRandomOracle[0], tagsRandomOracle[1])
	if err != nil {
		return nil, errs.WrapFailed(err, "creating popf")
	}
	return f, nil
}

func (p *Participant[GE, SE]) makeKeyAgreementTag(chi, l int, j byte) []byte {
	return slices.Concat([]byte(PopfKeyLabel), binary.LittleEndian.AppendUint32(nil, uint32(chi*p.l+l)), []byte{j})
}
