package mult

import (
	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/ot/extension/softspoken"
)

type Round1Output = softspoken.Round1Output

type Round2Output struct {
	COTeRound2Output *softspoken.Round2Output
	RTilde           curves.Scalar
	U                [L]curves.Scalar
	GammaA           [L]curves.Scalar

	_ helper_types.Incomparable
}

func (bob *Bob) Round1() (*Round1Output, error) {
	// step 1.1
	bob.Beta = make([][XiBytes]byte, 1) // LOTe = 1 for Forced Reuse
	if _, err := bob.prng.Read(bob.Beta[0][:]); err != nil {
		return nil, errs.WrapFailed(err, "could not sample beta")
	}

	// step 1.2
	for i := 0; i < L; i++ {
		bob.BTilde[i] = bob.Curve.Scalar().Zero()
		for j := 0; j < Xi; j++ {
			// constant time branching, because we'll add if even if we don't need it
			addedCurrent := bob.BTilde[i].Add(bob.gadget[0][j])
			originalCurrent := bob.BTilde[i]
			if bitstring.SelectBit(bob.Beta[0][:], j) == 0x01 {
				bob.BTilde[i] = addedCurrent
			} else {
				bob.BTilde[i] = originalCurrent
			}
		}
	}

	// step 1.3
	oTeReceiverOutput, COTeR1Output, err := bob.receiver.Round1ExtendAndProveConsistency(bob.Beta)
	if err != nil {
		return nil, errs.WrapFailed(err, "bob step 1.3")
	}
	bob.oTeReceiverOutput = oTeReceiverOutput

	return COTeR1Output, nil
}

func (alice *Alice) Round2(round1output *softspoken.Round1Output, a RvoleAliceInput) (*OutputShares, *Round2Output, error) {
	for i := 0; i < L; i++ {
		// step 2.1
		alice.aTilde[i] = alice.Curve.Scalar().Random(alice.prng)
		// step 2.2
		alice.aHat[i] = alice.Curve.Scalar().Random(alice.prng)
	}

	// step 2.3
	alpha := [L][Xi][2]curves.Scalar{}
	for i := 0; i < L; i++ {
		for j := 0; j < Xi; j++ {
			alpha[i][j][0] = alice.aTilde[i]
			alpha[i][j][1] = alice.aHat[i]
		}
	}

	// TODO: get rid of pointer stuff
	// step 2.4
	_, cOTeSenderOutputs, cOTeRound2Output, err := alice.sender.Round2ExtendAndCheckConsistency(round1output, alpha[:])
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
	chiTildeTranscript := alice.transcript.ExtractBytes("transcript state for Chi tilde", impl.WideFieldBytes)
	chiTilde := [L]curves.Scalar{}
	for i := 0; i < L; i++ {
		chiTilde[i] = alice.Curve.Scalar().Hash(append([]byte{1, byte(i)}, chiTildeTranscript...))
	}

	// step 2.7
	chiHatTranscript := alice.transcript.ExtractBytes("transcript state for Chi hat", impl.WideFieldBytes)
	chiHat := [L]curves.Scalar{}
	for i := 0; i < L; i++ {
		chiHat[i] = alice.Curve.Scalar().Hash(append([]byte{2, byte(i)}, chiHatTranscript...))
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
	rTilde := alice.Curve.Scalar().Hash(toBeHashed)
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
	coteReceiverOutput, err := bob.receiver.Round3Derandomize(round2output.COTeRound2Output, bob.oTeReceiverOutput)
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
	chiTildeTranscript := bob.transcript.ExtractBytes("transcript state for Chi tilde", impl.WideFieldBytes)
	chiTilde := [L]curves.Scalar{}
	for i := 0; i < L; i++ {
		chiTilde[i] = bob.Curve.Scalar().Hash(append([]byte{1, byte(i)}, chiTildeTranscript...))
	}

	// step 2.4
	chiHatTranscript := bob.transcript.ExtractBytes("transcript state for Chi hat", impl.WideFieldBytes)
	chiHat := [L]curves.Scalar{}
	for i := 0; i < L; i++ {
		chiHat[i] = bob.Curve.Scalar().Hash(append([]byte{2, byte(i)}, chiHatTranscript...))
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
			if bitstring.SelectBit(bob.Beta[0][:], j) == 0x01 {
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
	rTildeB := bob.Curve.Scalar().Hash(rhs)
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
