package mult

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
)

type Round1Output = softspoken.Round1Output

type Round2Output struct {
	COTeRound2Output *softspoken.Round2Output
	RTilde           curves.Scalar
	U                [L]curves.Scalar
	GammaA           [L]curves.Scalar

	_ types.Incomparable
}

func (bob *Bob) Round1() (*Round1Output, error) {
	// step 1.1
	bob.Beta = make([][XiBytes]byte, 1) // LOTe = 1 for Forced Reuse
	if _, err := bob.csrand.Read(bob.Beta[0][:]); err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not sample beta")
	}

	// step 1.2
	for i := 0; i < L; i++ {
		bob.BTilde[i] = bob.Curve.Scalar().Zero()
		for j := 0; j < Xi; j++ {
			// constant time branching, because we'll add if even if we don't need it
			addedCurrent := bob.BTilde[i].Add(bob.gadget[0][j])
			originalCurrent := bob.BTilde[i]
			bit, err := bitstring.SelectBit(bob.Beta[0][:], j)
			if err != nil {
				return nil, errs.WrapFailed(err, "bob failed to select bit")
			}
			if bit == 0x01 {
				bob.BTilde[i] = addedCurrent
			} else {
				bob.BTilde[i] = originalCurrent
			}
		}
	}

	// step 1.3
	_, COTeR1Output, err := bob.receiver.Round1(bob.Beta)
	if err != nil {
		return nil, errs.WrapFailed(err, "bob step 1.3")
	}

	return COTeR1Output, nil
}

func (alice *Alice) Round2(round1output *softspoken.Round1Output, a RvoleAliceInput) (s *OutputShares, r2o *Round2Output, err error) {
	for i := 0; i < L; i++ {
		// step 2.1
		alice.aTilde[i], err = alice.Curve.Scalar().Random(alice.csrand)
		if err != nil {
			return nil, nil, errs.WrapRandomSampleFailed(err, "alice failed to sample a tilde")
		}
		// step 2.2
		alice.aHat[i], err = alice.Curve.Scalar().Random(alice.csrand)
		if err != nil {
			return nil, nil, errs.WrapRandomSampleFailed(err, "alice failed to sample a hat")
		}
	}

	// step 2.3
	alpha := [L][Xi][]curves.Scalar{}
	for i := 0; i < L; i++ {
		for j := 0; j < Xi; j++ {
			alpha[i][j] = make([]curves.Scalar, 2)
			alpha[i][j][0] = alice.aTilde[i]
			alpha[i][j][1] = alice.aHat[i]
		}
	}

	// step 2.4
	_, cOTeSenderOutputs, cOTeRound2Output, err := alice.sender.Round2(round1output, alpha[:])
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "alice cote round 2")
	}

	// step 2.5
	zTildeA := [L][Xi]curves.Scalar{}
	zHatA := [L][Xi]curves.Scalar{}
	for i := 0; i < L; i++ {
		for j := 0; j < Xi; j++ {
			zTildeA[i][j] = (cOTeSenderOutputs)[0][j][0]
			zHatA[i][j] = (cOTeSenderOutputs)[1][j][1]
		}
	}

	// step 2.6
	chiTildeTranscript, err := alice.transcript.ExtractBytes("transcript state for Chi tilde", base.WideFieldBytes)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "alice failed to extract chi tilde transcript")
	}
	chiTilde, err := alice.Curve.HashToScalars(L, append([]byte{1}, chiTildeTranscript...), nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "alice failed to hash chi tilde")
	}

	// step 2.7
	chiHatTranscript, err := alice.transcript.ExtractBytes("transcript state for Chi hat", base.WideFieldBytes)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "alice failed to extract chi tilde transcript")
	}
	chiHat, err := alice.Curve.HashToScalars(L, append([]byte{2}, chiHatTranscript...), nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "alice failed to hash chi tilde")
	}

	// step 2.8
	u := [L]curves.Scalar{}
	for i := 0; i < L; i++ {
		u[i] = chiTilde[i].Mul(alice.aTilde[i]).Add(chiHat[i].Mul(alice.aHat[i]))
	}
	alice.transcript.AppendScalars("u", u[:]...)

	// step 2.9
	r := [Xi]curves.Scalar{}
	for j := 0; j < Xi; j++ {
		r[j] = alice.Curve.Scalar().Zero()
		for i := 0; i < L; i++ {
			r[j] = r[j].Add(chiTilde[i].Mul(zTildeA[i][j]))
			r[j] = r[j].Add(chiHat[i].Mul(zHatA[i][j]))
		}
	}

	// step 2.10
	toBeHashed := []byte{}
	toBeHashed = append(toBeHashed, alice.uniqueSessionId...)
	for _, element := range &r {
		toBeHashed = append(toBeHashed, element.Bytes()...)
	}
	rTilde, err := alice.Curve.Scalar().Hash(toBeHashed)
	if err != nil {
		return nil, nil, errs.WrapHashingFailed(err, "alice failed to hash r tilde")
	}
	alice.transcript.AppendScalars("rTilde", rTilde)

	// step 2.11
	for i := 0; i < L; i++ {
		alice.gammaA[i] = a[i].Sub(alice.aTilde[i])
	}
	alice.transcript.AppendScalars("Gamma_A", alice.gammaA[:]...)

	// step 2.12
	output := &OutputShares{}
	for i := 0; i < L; i++ {
		output[i] = alice.Curve.Scalar().Zero() // gamma_b of DKLs19 is zero
		for j := 0; j < Xi; j++ {
			output[i] = output[i].Add(alice.gadget[0][j].Mul(zTildeA[i][j]))
		}
	}

	return output, &Round2Output{
		COTeRound2Output: cOTeRound2Output,
		RTilde:           rTilde,
		U:                u,
		GammaA:           alice.gammaA,
	}, nil
}

func (bob *Bob) Round3(round2output *Round2Output) (output *OutputShares, err error) {
	// step 2.1
	coteReceiverOutput, err := bob.receiver.Round3(round2output.COTeRound2Output)
	if err != nil {
		return nil, errs.WrapFailed(err, "bob cote round 3")
	}
	// step 2.2
	zTildeB := [L][Xi]curves.Scalar{}
	zHatB := [L][Xi]curves.Scalar{}
	for i := 0; i < L; i++ {
		for j := 0; j < Xi; j++ {
			zTildeB[i][j] = coteReceiverOutput[i][j][0]
			zHatB[i][j] = coteReceiverOutput[i][j][1]
		}
	}

	// step 2.3
	chiTildeTranscript, err := bob.transcript.ExtractBytes("transcript state for Chi tilde", base.WideFieldBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "alice failed to extract chi tilde transcript")
	}
	chiTilde, err := bob.Curve.HashToScalars(L, append([]byte{1}, chiTildeTranscript...), nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "alice failed to hash chi tilde")
	}

	// step 2.4
	chiHatTranscript, err := bob.transcript.ExtractBytes("transcript state for Chi hat", base.WideFieldBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "alice failed to extract chi tilde transcript")
	}
	chiHat, err := bob.Curve.HashToScalars(L, append([]byte{2}, chiHatTranscript...), nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "alice failed to hash chi tilde")
	}

	// According to spec, Alice would have generated u right after producing chiTilde and chiHat
	bob.transcript.AppendScalars("u", round2output.U[:]...)

	// step 2.5
	rTildeBElements := [Xi]curves.Scalar{}
	for j := 0; j < Xi; j++ {
		current := bob.Curve.Scalar().Zero()
		for i := 0; i < L; i++ {
			// constant time branching
			addedCurrent := current.Add(round2output.U[i])
			originalCurrent := current
			bit, err := bitstring.SelectBit(bob.Beta[0][:], j)
			if err != nil {
				return nil, errs.WrapFailed(err, "bob failed to select bit")
			}
			if bit == 0x01 {
				current = addedCurrent
			} else {
				current = originalCurrent
			}
			current = current.
				Sub(chiTilde[i].Mul(zTildeB[i][j])).
				Sub(chiHat[i].Mul(zHatB[i][j]))
		}
		rTildeBElements[j] = current
	}
	rhs := []byte{}
	rhs = append(rhs, bob.uniqueSessionId...)
	for _, element := range &rTildeBElements {
		rhs = append(rhs, element.Bytes()...)
	}
	rTildeB, err := bob.Curve.Scalar().Hash(rhs)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "bob failed to hash r tilde")
	}
	// step 2.6
	if rTildeB.Cmp(round2output.RTilde) != 0 {
		return nil, errs.NewVerificationFailed("bob round 3 rtilde check")
	}
	bob.transcript.AppendScalars("rTilde", rTildeB)

	// step 2.7
	output = &OutputShares{}
	for i := 0; i < L; i++ {
		output[i] = bob.BTilde[i].Mul(round2output.GammaA[i])
		for j := 0; j < Xi; j++ {
			output[i] = output[i].Add(bob.gadget[0][j].Mul(zTildeB[i][j]))
		}
	}
	bob.transcript.AppendScalars("Gamma_A", round2output.GammaA[:]...)
	return output, nil
}
