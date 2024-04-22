package bbot

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/dh"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

const (
	PopfKeyLabel = "COPPER-BBOT-POPF-"
	Ro0Label     = "COPPER-BBOT-RO0-"
	Ro1Label     = "COPPER-BBOT-RO1-"
	TagLength    = ot.KappaBytes
)

func (s *Sender) Round1() (r1out *Round1P2P, err error) {
	// Validation
	if s.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, s.Round)
	}

	// step 1.1 (KA.R)
	s.MyEsk, err = s.Protocol.Curve().ScalarField().Random(s.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "generating random scalar a")
	}
	// step 1.2 (KA.msg_1)
	mS := s.Protocol.Curve().ScalarBaseMult(s.MyEsk)
	// step 1.3 (Setup RO)
	s.Transcript.AppendPoints("mS", mS)

	s.Round = 3
	return &Round1P2P{
		MS: mS,
	}, nil
}

func (r *Receiver) Round2(r1out *Round1P2P) (r2out *Round2P2P, err error) {
	// Validation
	if r.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, r.Round)
	}
	if err := r1out.Validate(r.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", r.Round)
	}

	phi := make([][2][]curves.Point, r.Protocol.Xi)
	r.Output.ChosenMessages = make([]ot.Message, r.Protocol.Xi)
	// Setup ROs
	r.Transcript.AppendPoints("mS", r1out.MS)
	var tagRandomOracle [2][]byte
	tagRandomOracle[0], err = r.Transcript.ExtractBytes(Ro0Label, TagLength)
	if err != nil {
		return nil, errs.WrapHashing(err, "extracting tag Ro0")
	}
	tagRandomOracle[1], err = r.Transcript.ExtractBytes(Ro1Label, TagLength)
	if err != nil {
		return nil, errs.WrapHashing(err, "extracting tag Ro1")
	}
	// step 2.1
	for i := 0; i < r.Protocol.Xi; i++ {
		c_i := r.Output.Choices.Get(i)
		phi[i] = [2][]curves.Point{make([]curves.Point, r.Protocol.L), make([]curves.Point, r.Protocol.L)}
		r.Output.ChosenMessages[i] = make(ot.Message, r.Protocol.L)
		for l := 0; l < r.Protocol.L; l++ {
			// step 2.2 (KA.R)
			b_i, err := r.Protocol.Curve().ScalarField().Random(r.Prng)
			if err != nil {
				return nil, errs.WrapRandomSample(err, "generating random scalar bi")
			}
			// step 2.3 (KA.msg_2)
			mR_i := r.Protocol.Curve().ScalarBaseMult(b_i)
			// step 2.4 (KA.key_2)
			sharedValue, err := dh.DiffieHellman(b_i, r1out.MS)
			if err != nil {
				return nil, errs.WrapFailed(err, "computing shared bytes for KA.key_2")
			}
			r_i_l, err := hashing.Hash(ot.HashFunction, sharedValue.Bytes(), []byte(PopfKeyLabel), bitstring.ToBytesLE(i*r.Protocol.L+l), []byte{c_i})
			if err != nil {
				return nil, errs.WrapHashing(err, "computing r_i_j")
			}
			copy(r.Output.ChosenMessages[i][l][:], r_i_l)
			// step 2.5 (POPF.Program)
			sc, err := r.Protocol.Curve().ScalarField().Random(r.Prng)
			if err != nil {
				return nil, errs.WrapRandomSample(err, "generating random scalar sc")
			}
			phi[i][1-c_i][l] = r.Protocol.Curve().ScalarBaseMult(sc).ClearCofactor()

			// step 2.6 (POPF.Program)
			hashInput := slices.Concat(phi[i][1-c_i][l].ToAffineCompressed(), tagRandomOracle[c_i])
			sc, err = r.Protocol.Curve().ScalarField().Hash(hashInput)
			if err != nil {
				return nil, errs.WrapHashing(err, "hashing phi[%d][%d]", i, 1-c_i)
			}
			pt := r.Protocol.Curve().ScalarBaseMult(sc).ClearCofactor()
			phi[i][c_i][l] = mR_i.Sub(pt)
		}
	}

	r.Round++
	return &Round2P2P{Phi: phi}, nil
}

func (s *Sender) Round3(r2out *Round2P2P) (err error) {
	// Validation
	if s.Round != 3 {
		return errs.NewRound("Running round %d but participant expected round %d", 3, s.Round)
	}
	if err := r2out.Validate(s.Protocol); err != nil {
		return errs.WrapValidation(err, "invalid round %d input", s.Round)
	}

	// Setup ROs
	tagRandomOracle := make([][]byte, 2)
	tagRandomOracle[0], err = s.Transcript.ExtractBytes(Ro0Label, TagLength)
	if err != nil {
		return errs.WrapHashing(err, "extracting tag Ro0")
	}
	tagRandomOracle[1], err = s.Transcript.ExtractBytes(Ro1Label, TagLength)
	if err != nil {
		return errs.WrapHashing(err, "extracting tag Ro1")
	}
	s.Output.MessagePairs = make([][2]ot.Message, s.Protocol.Xi)
	// step 3.1
	for i := 0; i < s.Protocol.Xi; i++ {
		s.Output.MessagePairs[i] = [2]ot.Message{make([]ot.MessageElement, s.Protocol.L), make([]ot.MessageElement, s.Protocol.L)}
		for l := 0; l < s.Protocol.L; l++ {
			for j := byte(0); j < 2; j++ {
				// step 3.2 (POPF.Eval)
				hashInput := slices.Concat(r2out.Phi[i][1-j][l].ToAffineCompressed(), tagRandomOracle[j])
				sc, err := s.Protocol.Curve().ScalarField().Hash(hashInput)
				if err != nil {
					return errs.WrapHashing(err, "hashing for phi[%d][%d]", i, j)
				}
				P := s.Protocol.Curve().ScalarBaseMult(sc).ClearCofactor().Add(r2out.Phi[i][j][l])
				// step 3.3 (KA.key_1)
				sharedValue, err := dh.DiffieHellman(s.MyEsk, P)
				if err != nil {
					return errs.WrapFailed(err, "computing shared bytes for KA.key_2")
				}
				sharedValueBytes := sharedValue.Bytes()
				s_i_l, err := hashing.Hash(ot.HashFunction, sharedValueBytes, []byte(PopfKeyLabel), bitstring.ToBytesLE(i*s.Protocol.L+l), []byte{j})
				if err != nil {
					return errs.WrapHashing(err, "computing s_i_j")
				}
				copy(s.Output.MessagePairs[i][j][l][:], s_i_l)
			}
		}
	}

	s.Round++
	return nil
}
