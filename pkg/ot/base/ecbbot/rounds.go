package ecbbot

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

const (
	TaggedKeyAgreementMs = "BRON_CRYPTO-BBOT-KA-MA-"
	PopfKeyLabel         = "BRON_CRYPTO-BBOT-POPF-"
	Ro0Label             = "BRON_CRYPTO-BBOT-RO0-"
	Ro1Label             = "BRON_CRYPTO-BBOT-RO1-"
	TagLength            = 16
)

// Round1 runs the sender's first round: sample a, send key agreement message.
func (s *Sender[G, S]) Round1() (r1out *Round1P2P[G, S], err error) {
	// Validation
	if s.round != 1 {
		return nil, ot.ErrRound.WithMessage("running round %d but participant expected round %d", 1, s.round)
	}

	// step 1.1 (KA.R)
	s.state.a, err = s.ka.R(s.prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("generating a")
	}

	// step 1.2 (KA.msg_1)
	ms, err := s.ka.Msg1(s.state.a)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("creating msg1")
	}

	// step 1.3 (Setup RO)
	s.tape.AppendBytes(TaggedKeyAgreementMs, ms.Bytes())

	s.round = 3
	r1out = &Round1P2P[G, S]{
		Ms: ms,
	}
	return r1out, nil
}

// Round2 completes key agreement per choice bit, programs POPF, and returns receiver output.
func (r *Receiver[G, S]) Round2(r1out *Round1P2P[G, S], choices []byte) (r2out *Round2P2P[G, S], receiverOut *ReceiverOutput[S], err error) {
	// Validation
	if r.round != 2 {
		return nil, nil, ot.ErrRound.WithMessage("running round %d but participant expected round %d", 2, r.round)
	}

	// Setup ROs
	r.tape.AppendBytes(TaggedKeyAgreementMs, r1out.Ms.Bytes())
	f, err := r.makeProgrammableOncePublicFunction()
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("creating popf")
	}

	// step 2.1
	phi := make([][2][]G, r.suite.Xi())
	receiverOut = NewReceiverOutput[S](r.suite.Xi(), r.suite.L())
	receiverOut.Choices = choices
	for i := range r.suite.Xi() {
		ci := (choices[i/8] >> (i % 8)) & 0b1
		phi[i] = [2][]G{make([]G, r.suite.L()), make([]G, r.suite.L())}
		for l := range r.suite.L() {
			// step 2.2 (KA.R)
			bi, err := r.ka.R(r.prng)
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("generating random scalar bi")
			}

			// step 2.3 (KA.msg_2)
			mRi, err := r.ka.Msg2(bi, r1out.Ms)
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("creating msg2")
			}

			// step 2.4 (KA.key_2)
			tag := r.makeKeyAgreementTag(i, l, ci)
			receiverOut.Messages[i][l], err = r.ka.Key2(bi, r1out.Ms, tag)
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("computing shared bytes for KA.key_2")
			}

			// step 2.5,2.6 (POPF.Program)
			phi[i][0][l], phi[i][1][l], err = f.Program(ci, mRi, r.prng)
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("generating random scalar sc")
			}
		}
	}

	r.round++
	r2out = &Round2P2P[G, S]{Phi: phi}
	return r2out, receiverOut, nil
}

// Round3 evaluates the programmed POPF and derives sender outputs for both branches.
func (s *Sender[G, S]) Round3(r2out *Round2P2P[G, S]) (senderOut *SenderOutput[S], err error) {
	// Validation
	if s.round != 3 {
		return nil, ot.ErrRound.WithMessage("running round %d but participant expected round %d", 3, s.round)
	}

	f, err := s.makeProgrammableOncePublicFunction()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("creating popf")
	}

	// step 3.1
	senderOut = NewSenderOutput[S](s.suite.Xi(), s.suite.L())
	for i := range s.suite.Xi() {
		for l := range s.suite.L() {
			for j := range byte(2) {
				// step 3.2 (POPF.Eval)
				p, err := f.Eval(r2out.Phi[i][0][l], r2out.Phi[i][1][l], j)
				if err != nil {
					return nil, errs2.Wrap(err).WithMessage("popf eval")
				}

				// step 3.3 (KA.key_1)
				tag := s.makeKeyAgreementTag(i, l, j)
				senderOut.Messages[i][j][l], err = s.ka.Key2(s.state.a, p, tag)
				if err != nil {
					return nil, errs2.Wrap(err).WithMessage("computing shared bytes for KA.key_2")
				}
			}
		}
	}

	s.round++
	return senderOut, nil
}

func (p *participant[G, S]) makeProgrammableOncePublicFunction() (f *Popf[G, S], err error) {
	var tagsRandomOracle [2][]byte
	tagsRandomOracle[0], err = p.tape.ExtractBytes(Ro0Label, TagLength)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("extracting tag Ro0")
	}
	tagsRandomOracle[1], err = p.tape.ExtractBytes(Ro1Label, TagLength)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("extracting tag Ro1")
	}
	f, err = NewPopf(p.suite.Group(), tagsRandomOracle[0], tagsRandomOracle[1])
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("creating popf")
	}
	return f, nil
}

func (p *participant[G, S]) makeKeyAgreementTag(xi, l int, j byte) []byte {
	return slices.Concat([]byte(PopfKeyLabel), binary.LittleEndian.AppendUint32(nil, uint32(xi*p.suite.L()+l)), []byte{j})
}
