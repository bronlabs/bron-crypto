package bbot

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/ecsvdp/dhc"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

const (
	PopfKeyLabel = "COPPER-BBOT-POPF"
	Ro0Label     = "COPPER-BBOT-RO0"
	Ro1Label     = "COPPER-BBOT-RO1"
	TagLength    = ot.KappaBytes
)

type (
	Round1P2P = curves.Point        // mS
	Round2P2P = [][2][]curves.Point // phi ∈ [ξ][2][L]Point
)

func (S *Sender) Round1() (mS Round1P2P, err error) {
	// step 1.1 (KA.R)
	S.MyEsk, err = S.Curve.ScalarField().Random(S.Csprng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "generating random scalar a")
	}
	// step 1.2 (KA.msg_1)
	mS = S.Curve.ScalarBaseMult(S.MyEsk)
	// step 1.3 (Setup RO)
	S.Transcript.AppendPoints("mS", mS)
	return mS, nil
}

func (R *Receiver) Round2(mS Round1P2P) (r2out Round2P2P, err error) {
	// step 2.1
	if len(R.Output.Choices) == 0 {
		R.Output.Choices = make(ot.ChoiceBits, R.Xi/8)
		if _, err := R.Csprng.Read(R.Output.Choices); err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "generating random choice bits")
		}
	}
	phi := make([][2][]curves.Point, R.Xi)
	R.Output.ChosenMessages = make([]ot.ChosenMessage, R.Xi)
	// step 2.2 (Setup RO)
	R.Transcript.AppendPoints("mS", mS)
	var tagRandomOracle [2][]byte
	tagRandomOracle[0], err = R.Transcript.ExtractBytes(Ro0Label, TagLength)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "extracting tag Ro0")
	}
	tagRandomOracle[1], err = R.Transcript.ExtractBytes(Ro1Label, TagLength)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "extracting tag Ro1")
	}
	// step 2.3
	for i := 0; i < R.Xi; i++ {
		c_i := bitstring.SelectBit(R.Output.Choices, i)
		phi[i] = [2][]curves.Point{make([]curves.Point, R.L), make([]curves.Point, R.L)}
		R.Output.ChosenMessages[i] = make(ot.ChosenMessage, R.L)
		for l := 0; l < R.L; l++ {
			// step 2.2.1 (KA.R)
			b_i, err := R.Curve.ScalarField().Random(R.Csprng)
			if err != nil {
				return nil, errs.WrapRandomSampleFailed(err, "generating random scalar bi")
			}
			// step 2.2.2 (KA.msg_2)
			mR_i := R.Curve.ScalarBaseMult(b_i)
			// step 2.2.3 (KA.key_2)
			sharedValue, err := dhc.DeriveSharedSecretValue(b_i, mS)
			if err != nil {
				return nil, errs.WrapFailed(err, "computing shared bytes for KA.key_2")
			}
			r_i_l, err := hashing.Hash(ot.HashFunction, sharedValue.Bytes(), []byte(PopfKeyLabel), bitstring.ToBytesLE(i*R.L+l), []byte{c_i})
			if err != nil {
				return nil, errs.WrapHashingFailed(err, "computing r_i_j")
			}
			copy(R.Output.ChosenMessages[i][l][:], r_i_l)
			// step 2.2.4 (POPF.Program I)
			sc, err := R.Curve.ScalarField().Random(R.Csprng)
			if err != nil {
				return nil, errs.WrapRandomSampleFailed(err, "generating random scalar sc")
			}
			phi[i][1-c_i][l] = R.Curve.ScalarBaseMult(sc).ClearCofactor()

			// step 2.2.5 (POPF.Program II)
			hashInput := bytes.Join([][]byte{phi[i][1-c_i][l].ToAffineCompressed(), tagRandomOracle[c_i]}, nil)
			sc, err = R.Curve.ScalarField().Hash(hashInput)
			if err != nil {
				return nil, errs.WrapHashingFailed(err, "hashing phi[%d][%d]", i, 1-c_i)
			}
			pt := R.Curve.ScalarBaseMult(sc).ClearCofactor()
			phi[i][c_i][l] = mR_i.Sub(pt)
		}
	}
	return phi, nil
}

func (S *Sender) Round3(phi Round2P2P) (err error) {
	if len(phi) != S.Xi {
		return errs.NewInvalidArgument("phi length should be Xi (%d != %d)", len(phi), S.Xi)
	}
	// step 3.1 (Setup RO)
	tagRandomOracle := make([][]byte, 2)
	tagRandomOracle[0], err = S.Transcript.ExtractBytes(Ro0Label, TagLength)
	if err != nil {
		return errs.WrapHashingFailed(err, "extracting tag Ro0")
	}
	tagRandomOracle[1], err = S.Transcript.ExtractBytes(Ro1Label, TagLength)
	if err != nil {
		return errs.WrapHashingFailed(err, "extracting tag Ro1")
	}
	S.Output.Messages = make([]ot.MessagePair, S.Xi)
	for i := 0; i < S.Xi; i++ {
		if len(phi[i][0]) != S.L || len(phi[i][1]) != S.L {
			return errs.NewInvalidArgument("phi[%d] length should be L (%d != %d || %d != %d)",
				i, len(phi[i][0]), S.L, len(phi[i][1]), S.L)
		}
		S.Output.Messages[i] = ot.MessagePair{make([]ot.MessageElement, S.L), make([]ot.MessageElement, S.L)}
		for l := 0; l < S.L; l++ {
			for j := byte(0); j < 2; j++ {
				// step 3.1.1 (POPF.Eval)
				hashInput := bytes.Join([][]byte{phi[i][1-j][l].ToAffineCompressed(), tagRandomOracle[j]}, nil)
				sc, err := S.Curve.ScalarField().Hash(hashInput)
				if err != nil {
					return errs.WrapHashingFailed(err, "hashing for phi[%d][%d]", i, j)
				}
				P := S.Curve.ScalarBaseMult(sc).ClearCofactor().Add(phi[i][j][l])
				// step 3.1.2 (KA.key_1)
				sharedValue, err := dhc.DeriveSharedSecretValue(S.MyEsk, P)
				if err != nil {
					return errs.WrapFailed(err, "computing shared bytes for KA.key_2")
				}
				sharedValueBytes := sharedValue.Bytes()
				s_i_l, err := hashing.Hash(ot.HashFunction, sharedValueBytes, []byte(PopfKeyLabel), bitstring.ToBytesLE(i*S.L+l), []byte{j})
				if err != nil {
					return errs.WrapHashingFailed(err, "computing s_i_j")
				}
				copy(S.Output.Messages[i][j][l][:], s_i_l)
			}
		}
	}
	return nil
}
