package mul_bbot

import (
	"bytes"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func (alice *Alice[GE, SE]) Round1() (r1Out *Round1P2P[GE, SE], err error) {
	if alice.Round != 1 {
		return nil, errs.NewValidation("invalid round")
	}

	r1Out, err = alice.sender.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to call OT round 1")
	}

	alice.Round += 2
	return r1Out, nil
}

func (bob *Bob[GE, SE]) Round2(r1Out *Round1P2P[GE, SE]) (r2Out *Round2P2P[GE, SE], b SE, err error) {
	var nilSE SE
	if bob.Round != 2 {
		return nil, nilSE, errs.NewValidation("invalid round")
	}

	beta := make([]byte, bob.Xi/8)
	if _, err := io.ReadFull(bob.Prng, beta); err != nil {
		return nil, nilSE, errs.WrapRandomSample(err, "cannot sample choices")
	}

	r2Out, receiverOutput, err := bob.receiver.Round2(r1Out, beta)
	if err != nil {
		return nil, nilSE, errs.WrapFailed(err, "cannot run round 2 of receiver")
	}
	bob.beta = receiverOutput.Choices
	bob.gamma = receiverOutput.R

	b = bob.ScalarField.Zero()
	for j := 0; j < bob.Xi; j++ {
		betaJ := bob.ScalarField.Zero()
		ci := (bob.beta[j/8] >> (j % 8)) & 0b1
		if ci != 0 {
			betaJ = bob.ScalarField.One()
		}
		b = b.Add(betaJ.Mul(bob.g[j]))
	}

	bob.Round += 2
	return r2Out, b, nil
}

func (alice *Alice[GE, SE]) Round3(r2Out *Round2P2P[GE, SE], a []SE) (r3Out *Round3P2P[SE], c []SE, err error) {
	if alice.Round != 3 {
		return nil, nil, errs.NewValidation("invalid round")
	}

	senderOutput, err := alice.sender.Round3(r2Out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot send round 3 of receiver")
	}
	alice.alpha = senderOutput.S

	c = make([]SE, alice.L)
	for i := range alice.L {
		c[i] = alice.ScalarField.Zero()
		for j := range alice.Xi {
			c[i] = c[i].Sub(alice.g[j].Mul(alice.alpha[j][0][i]))
		}
	}

	aHat := make([]SE, alice.Rho)
	for i := range alice.Rho {
		aHat[i], err = alice.ScalarField.Random(alice.Prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot get random scalar")
		}
	}

	aTilde := make([][]SE, alice.Xi)
	for j := range alice.Xi {
		aTilde[j] = make([]SE, alice.L+alice.Rho)
		for i := range alice.L {
			aTilde[j][i] = alice.alpha[j][0][i].Sub(alice.alpha[j][1][i]).Add(a[i])
		}
		for k := range alice.Rho {
			aTilde[j][alice.L+k] = alice.alpha[j][0][alice.L+k].Sub(alice.alpha[j][1][alice.L+k]).Add(aHat[k])
		}
	}

	theta, err := alice.roTheta(aTilde)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot get theta")
	}

	eta := make([]SE, alice.Rho)
	for k := range alice.Rho {
		eta[k] = aHat[k]
		for i := range alice.L {
			eta[k] = eta[k].Add(theta[i][k].Mul(a[i]))
		}
	}

	muBold := make([][]SE, alice.Xi)
	for j := range alice.Xi {
		muBold[j] = make([]SE, alice.Rho)
		for k := range alice.Rho {
			muBold[j][k] = alice.alpha[j][0][alice.L+k]
			for i := range alice.L {
				muBold[j][k] = muBold[j][k].Add(theta[i][k].Mul(alice.alpha[j][0][i]))
			}
		}
	}

	mu, err := alice.roMu(muBold)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot get mu")
	}

	r3Out = &Round3P2P[SE]{
		ATilde: aTilde,
		Eta:    eta,
		Mu:     mu,
	}
	alice.Round += 2
	return r3Out, c, nil
}

func (bob *Bob[GE, SE]) Round4(r3Out *Round3P2P[SE]) (d []SE, err error) {
	if bob.Round != 4 {
		return nil, errs.NewValidation("invalid round")
	}
	//if err := r3Out.Validate(bob.Protocol); err != nil {
	//	return nil, errs.WrapFailed(err, "invalid message")
	//}

	theta, err := bob.roTheta(r3Out.ATilde)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get theta")
	}

	dDot := make([][]SE, bob.Xi)
	for j := range bob.Xi {
		dDot[j] = make([]SE, bob.L)
		betaJ := bob.ScalarField.Zero()
		ci := (bob.beta[j/8] >> (j % 8)) & 0b1
		if ci != 0 {
			betaJ = bob.ScalarField.One()
		}
		for i := range bob.L {
			dDot[j][i] = bob.gamma[j][i].Add(betaJ.Mul(r3Out.ATilde[j][i]))
		}
	}

	dHat := make([][]SE, bob.Xi)
	for j := range bob.Xi {
		dHat[j] = make([]SE, bob.Rho)
		betaJ := bob.ScalarField.Zero()
		ci := (bob.beta[j/8] >> (j % 8)) & 0b1
		if ci != 0 {
			betaJ = bob.ScalarField.One()
		}
		for k := range bob.Rho {
			dHat[j][k] = bob.gamma[j][bob.L+k].Add(betaJ.Mul(r3Out.ATilde[j][bob.L+k]))
		}
	}

	muPrimeBold := make([][]SE, bob.Xi)
	for j := range bob.Xi {
		muPrimeBold[j] = make([]SE, bob.Rho)
		betaJ := bob.ScalarField.Zero()
		ci := (bob.beta[j/8] >> (j % 8)) & 0b1
		if ci != 0 {
			betaJ = bob.ScalarField.One()
		}
		for k := range bob.Rho {
			muPrimeBold[j][k] = dHat[j][k].Sub(betaJ.Mul(r3Out.Eta[k]))
			for i := range bob.L {
				muPrimeBold[j][k] = muPrimeBold[j][k].Add(theta[i][k].Mul(dDot[j][i]))
			}
		}
	}

	mu, err := bob.roMu(muPrimeBold)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get mu")
	}
	if !bytes.Equal(r3Out.Mu, mu) {
		return nil, errs.NewTotalAbort("alice", "consistency check failed")
	}

	d = make([]SE, bob.L)
	for i := range bob.L {
		d[i] = bob.ScalarField.Zero()
		for j := range bob.Xi {
			d[i] = d[i].Add(bob.g[j].Mul(dDot[j][i]))
		}
	}

	bob.Round += 2
	return d, nil
}

func (p *participant[GE, SE]) roTheta(aTilde [][]SE) (theta [][]SE, err error) {
	for _, aTildeJ := range aTilde {
		for _, aj := range aTildeJ {
			p.Tape.AppendBytes(aTildeLabel, aj.Bytes())
		}
	}

	theta = make([][]SE, p.L)
	for i := range theta {
		theta[i] = make([]SE, p.Rho)
		for j := range theta[i] {
			thetaBytes, err := p.Tape.ExtractBytes(thetaLabel, uint(p.ScalarField.WideElementSize()))
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot extract theta")
			}
			theta[i][j], err = p.ScalarField.FromWideBytes(thetaBytes)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot set theta")
			}
		}
	}

	return theta, nil
}

func (p *participant[GE, SE]) roMu(muBold [][]SE) (mu []byte, err error) {
	for _, muJ := range muBold {
		for _, e := range muJ {
			p.Tape.AppendBytes(muVectorLabel, e.Bytes())
		}
	}
	mu, err = p.Tape.ExtractBytes(muLabel, uint(base.CollisionResistanceBytesCeil))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract mu")
	}
	return mu, nil
}
