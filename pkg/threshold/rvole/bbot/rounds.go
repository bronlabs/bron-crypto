package rvole_bbot

import (
	"bytes"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func (alice *Alice[G, S]) Round1() (r1Out *Round1P2P[G, S], err error) {
	if alice.round != 1 {
		return nil, errs.NewValidation("invalid round")
	}

	r1Out, err = alice.sender.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to call OT round 1")
	}

	alice.round += 2
	return r1Out, nil
}

func (bob *Bob[G, S]) Round2(r1Out *Round1P2P[G, S]) (r2Out *Round2P2P[G, S], b S, err error) {
	var nilSE S
	if bob.round != 2 {
		return nil, nilSE, errs.NewValidation("invalid round")
	}

	beta := make([]byte, bob.xi/8)
	if _, err := io.ReadFull(bob.prng, beta); err != nil {
		return nil, nilSE, errs.WrapRandomSample(err, "cannot sample choices")
	}

	r2Out, receiverOutput, err := bob.receiver.Round2(r1Out, beta)
	if err != nil {
		return nil, nilSE, errs.WrapFailed(err, "cannot run round 2 of receiver")
	}
	bob.beta = receiverOutput.Choices
	bob.gamma = receiverOutput.Messages

	b = bob.suite.field.Zero()
	for j := range bob.xi {
		betaJ := bob.suite.field.Zero()
		ci := (bob.beta[j/8] >> (j % 8)) & 0b1
		if ci != 0 {
			betaJ = bob.suite.field.One()
		}
		b = b.Add(betaJ.Mul(bob.g[j]))
	}

	bob.round += 2
	return r2Out, b, nil
}

func (alice *Alice[G, S]) Round3(r2Out *Round2P2P[G, S], a []S) (r3Out *Round3P2P[S], c []S, err error) {
	if alice.round != 3 {
		return nil, nil, errs.NewValidation("invalid round")
	}

	senderOutput, err := alice.sender.Round3(r2Out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot send round 3 of receiver")
	}
	alice.alpha = senderOutput.Messages

	c = make([]S, alice.suite.l)
	for i := range alice.suite.l {
		c[i] = alice.suite.field.Zero()
		for j := range alice.xi {
			c[i] = c[i].Sub(alice.g[j].Mul(alice.alpha[j][0][i]))
		}
	}

	aHat := make([]S, alice.rho)
	for i := range alice.rho {
		aHat[i], err = alice.suite.field.Random(alice.prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot get random scalar")
		}
	}

	aTilde := make([][]S, alice.xi)
	for j := range alice.xi {
		aTilde[j] = make([]S, alice.suite.l+alice.rho)
		for i := range alice.suite.l {
			aTilde[j][i] = alice.alpha[j][0][i].Sub(alice.alpha[j][1][i]).Add(a[i])
		}
		for k := range alice.rho {
			aTilde[j][alice.suite.l+k] = alice.alpha[j][0][alice.suite.l+k].Sub(alice.alpha[j][1][alice.suite.l+k]).Add(aHat[k])
		}
	}

	theta, err := alice.roTheta(aTilde)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot get theta")
	}

	eta := make([]S, alice.rho)
	for k := range alice.rho {
		eta[k] = aHat[k]
		for i := range alice.suite.l {
			eta[k] = eta[k].Add(theta[i][k].Mul(a[i]))
		}
	}

	muBold := make([][]S, alice.xi)
	for j := range alice.xi {
		muBold[j] = make([]S, alice.rho)
		for k := range alice.rho {
			muBold[j][k] = alice.alpha[j][0][alice.suite.l+k]
			for i := range alice.suite.l {
				muBold[j][k] = muBold[j][k].Add(theta[i][k].Mul(alice.alpha[j][0][i]))
			}
		}
	}

	mu, err := alice.roMu(muBold)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot get mu")
	}

	r3Out = &Round3P2P[S]{
		ATilde: aTilde,
		Eta:    eta,
		Mu:     mu,
	}
	alice.round += 2
	return r3Out, c, nil
}

func (bob *Bob[G, S]) Round4(r3Out *Round3P2P[S]) (d []S, err error) {
	if bob.round != 4 {
		return nil, errs.NewValidation("invalid round")
	}
	// if err := r3Out.Validate(bob.Protocol); err != nil {
	//	return nil, errs.WrapFailed(err, "invalid message")
	//}

	theta, err := bob.roTheta(r3Out.ATilde)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get theta")
	}

	dDot := make([][]S, bob.xi)
	for j := range bob.xi {
		dDot[j] = make([]S, bob.suite.l)
		betaJ := bob.suite.field.Zero()
		ci := (bob.beta[j/8] >> (j % 8)) & 0b1
		if ci != 0 {
			betaJ = bob.suite.field.One()
		}
		for i := range bob.suite.l {
			dDot[j][i] = bob.gamma[j][i].Add(betaJ.Mul(r3Out.ATilde[j][i]))
		}
	}

	dHat := make([][]S, bob.xi)
	for j := range bob.xi {
		dHat[j] = make([]S, bob.rho)
		betaJ := bob.suite.field.Zero()
		ci := (bob.beta[j/8] >> (j % 8)) & 0b1
		if ci != 0 {
			betaJ = bob.suite.field.One()
		}
		for k := range bob.rho {
			dHat[j][k] = bob.gamma[j][bob.suite.l+k].Add(betaJ.Mul(r3Out.ATilde[j][bob.suite.l+k]))
		}
	}

	muPrimeBold := make([][]S, bob.xi)
	for j := range bob.xi {
		muPrimeBold[j] = make([]S, bob.rho)
		betaJ := bob.suite.field.Zero()
		ci := (bob.beta[j/8] >> (j % 8)) & 0b1
		if ci != 0 {
			betaJ = bob.suite.field.One()
		}
		for k := range bob.rho {
			muPrimeBold[j][k] = dHat[j][k].Sub(betaJ.Mul(r3Out.Eta[k]))
			for i := range bob.suite.l {
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

	d = make([]S, bob.suite.l)
	for i := range bob.suite.l {
		d[i] = bob.suite.field.Zero()
		for j := range bob.xi {
			d[i] = d[i].Add(bob.g[j].Mul(dDot[j][i]))
		}
	}

	bob.round += 2
	return d, nil
}

func (p *participant[G, S]) roTheta(aTilde [][]S) (theta [][]S, err error) {
	for _, aTildeJ := range aTilde {
		for _, aj := range aTildeJ {
			p.tape.AppendBytes(aTildeLabel, aj.Bytes())
		}
	}

	theta = make([][]S, p.suite.l)
	for i := range theta {
		theta[i] = make([]S, p.rho)
		for j := range theta[i] {
			thetaBytes, err := p.tape.ExtractBytes(thetaLabel, uint(p.suite.field.WideElementSize()))
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot extract theta")
			}
			theta[i][j], err = p.suite.field.FromWideBytes(thetaBytes)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot set theta")
			}
		}
	}

	return theta, nil
}

func (p *participant[G, S]) roMu(muBold [][]S) (mu []byte, err error) {
	for _, muJ := range muBold {
		for _, e := range muJ {
			p.tape.AppendBytes(muVectorLabel, e.Bytes())
		}
	}
	mu, err = p.tape.ExtractBytes(muLabel, uint(base.CollisionResistanceBytesCeil))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract mu")
	}
	return mu, nil
}
