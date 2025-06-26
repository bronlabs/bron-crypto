package dkls23_bbot

import (
	"bytes"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

func (alice *Alice) Round1() (r1Out *Round1P2P, err error) {
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

func (bob *Bob) Round2(r1Out *Round1P2P) (r2Out *Round2P2P, b curves.Scalar, err error) {
	if bob.Round != 2 {
		return nil, nil, errs.NewValidation("invalid round")
	}

	beta := make([]byte, bob.Protocol.Xi/8)
	if _, err := io.ReadFull(bob.Prng, beta); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample choices")
	}

	r2Out, receiverOutput, err := bob.receiver.Round2(r1Out, beta)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run round 2 of receiver")
	}
	bob.beta = receiverOutput.Choices
	bob.gamma = receiverOutput.R

	b = bob.Protocol.Curve().ScalarField().AdditiveIdentity()
	for j := 0; j < bob.Protocol.Xi; j++ {
		betaJ := bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		if bob.beta.Get(uint(j)) != 0 {
			betaJ = bob.Protocol.Curve().ScalarField().MultiplicativeIdentity()
		}
		b = b.Add(betaJ.Mul(bob.g[j]))
	}

	bob.Round += 2
	return r2Out, b, nil
}

func (alice *Alice) Round3(r2Out *Round2P2P, a []curves.Scalar) (r3Out *Round3P2P, c []curves.Scalar, err error) {
	if alice.Round != 3 {
		return nil, nil, errs.NewValidation("invalid round")
	}

	senderOutput, err := alice.sender.Round3(r2Out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot send round 3 of receiver")
	}
	alice.alpha = senderOutput.S

	c = make([]curves.Scalar, alice.Protocol.L)
	for i := range alice.Protocol.L {
		c[i] = alice.Protocol.Curve().ScalarField().AdditiveIdentity()
		for j := range alice.Protocol.Xi {
			c[i] = c[i].Sub(alice.g[j].Mul(alice.alpha[j][0][i]))
		}
	}

	aHat := make([]curves.Scalar, alice.Protocol.Rho)
	for i := range alice.Protocol.Rho {
		aHat[i], err = alice.Protocol.Curve().ScalarField().Random(alice.Prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot get random scalar")
		}
	}

	aTilde := make([][]curves.Scalar, alice.Protocol.Xi)
	for j := range alice.Protocol.Xi {
		aTilde[j] = make([]curves.Scalar, alice.Protocol.L+alice.Protocol.Rho)
		for i := range alice.Protocol.L {
			aTilde[j][i] = alice.alpha[j][0][i].Sub(alice.alpha[j][1][i]).Add(a[i])
		}
		for k := range alice.Protocol.Rho {
			aTilde[j][alice.Protocol.L+k] = alice.alpha[j][0][alice.Protocol.L+k].Sub(alice.alpha[j][1][alice.Protocol.L+k]).Add(aHat[k])
		}
	}

	theta, err := alice.roTheta(aTilde)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot get theta")
	}

	eta := make([]curves.Scalar, alice.Protocol.Rho)
	for k := range alice.Protocol.Rho {
		eta[k] = aHat[k]
		for i := range alice.Protocol.L {
			eta[k] = eta[k].Add(theta[i][k].Mul(a[i]))
		}
	}

	muBold := make([][]curves.Scalar, alice.Protocol.Xi)
	for j := range alice.Protocol.Xi {
		muBold[j] = make([]curves.Scalar, alice.Protocol.Rho)
		for k := range alice.Protocol.Rho {
			muBold[j][k] = alice.alpha[j][0][alice.Protocol.L+k]
			for i := range alice.Protocol.L {
				muBold[j][k] = muBold[j][k].Add(theta[i][k].Mul(alice.alpha[j][0][i]))
			}
		}
	}

	mu, err := alice.roMu(muBold)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot get mu")
	}

	r3Out = &Round3P2P{
		ATilde: aTilde,
		Eta:    eta,
		Mu:     mu,
	}
	alice.Round += 2
	return r3Out, c, nil
}

func (bob *Bob) Round4(r3Out *Round3P2P) (d []curves.Scalar, err error) {
	if bob.Round != 4 {
		return nil, errs.NewValidation("invalid round")
	}
	if err := r3Out.Validate(bob.Protocol); err != nil {
		return nil, errs.WrapFailed(err, "invalid message")
	}

	theta, err := bob.roTheta(r3Out.ATilde)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get theta")
	}

	dDot := make([][]curves.Scalar, bob.Protocol.Xi)
	for j := range bob.Protocol.Xi {
		dDot[j] = make([]curves.Scalar, bob.Protocol.L)
		betaJ := bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		if bob.beta.Get(uint(j)) != 0 {
			betaJ = bob.Protocol.Curve().ScalarField().MultiplicativeIdentity()
		}
		for i := range bob.Protocol.L {
			dDot[j][i] = bob.gamma[j][i].Add(betaJ.Mul(r3Out.ATilde[j][i]))
		}
	}

	dHat := make([][]curves.Scalar, bob.Protocol.Xi)
	for j := range bob.Protocol.Xi {
		dHat[j] = make([]curves.Scalar, bob.Protocol.Rho)
		betaJ := bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		if bob.beta.Get(uint(j)) != 0 {
			betaJ = bob.Protocol.Curve().ScalarField().MultiplicativeIdentity()
		}
		for k := range bob.Protocol.Rho {
			dHat[j][k] = bob.gamma[j][bob.Protocol.L+k].Add(betaJ.Mul(r3Out.ATilde[j][bob.Protocol.L+k]))
		}
	}

	muPrimeBold := make([][]curves.Scalar, bob.Protocol.Xi)
	for j := range bob.Protocol.Xi {
		muPrimeBold[j] = make([]curves.Scalar, bob.Protocol.Rho)
		betaJ := bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		if bob.beta.Get(uint(j)) != 0 {
			betaJ = bob.Protocol.Curve().ScalarField().MultiplicativeIdentity()
		}
		for k := range bob.Protocol.Rho {
			muPrimeBold[j][k] = dHat[j][k].Sub(betaJ.Mul(r3Out.Eta[k]))
			for i := range bob.Protocol.L {
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

	d = make([]curves.Scalar, bob.Protocol.L)
	for i := range bob.Protocol.L {
		d[i] = bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		for j := range bob.Protocol.Xi {
			d[i] = d[i].Add(bob.g[j].Mul(dDot[j][i]))
		}
	}

	bob.Round += 2
	return d, nil
}

func (p *participant) roTheta(aTilde [][]curves.Scalar) (theta [][]curves.Scalar, err error) {
	for _, aTildeJ := range aTilde {
		p.Tape.AppendScalars(aTildeLabel, aTildeJ...)
	}

	theta = make([][]curves.Scalar, p.Protocol.L)
	for i := range theta {
		theta[i] = make([]curves.Scalar, p.Protocol.Rho)
		for j := range theta[i] {
			thetaBytes, err := p.Tape.ExtractBytes(thetaLabel, uint(p.Protocol.Curve().ScalarField().WideElementSize()))
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot extract theta")
			}
			theta[i][j], err = p.Protocol.Curve().ScalarField().Element().SetBytesWide(thetaBytes)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot set theta")
			}
		}
	}

	return theta, nil
}

func (p *participant) roMu(muBold [][]curves.Scalar) (mu []byte, err error) {
	for _, muJ := range muBold {
		p.Tape.AppendScalars(muVectorLabel, muJ...)
	}
	mu, err = p.Tape.ExtractBytes(muLabel, uint(utils.CeilDiv(2*base.ComputationalSecurity, 8)))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract mu")
	}
	return mu, nil
}
