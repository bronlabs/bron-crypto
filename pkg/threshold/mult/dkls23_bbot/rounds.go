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
	r1Out, err = alice.sender.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to call OT round 1")
	}

	return r1Out, nil
}

func (bob *Bob) Round2(r1Out *Round1P2P) (r2Out *Round2P2P, b curves.Scalar, err error) {
	beta := make([]byte, bob.Xi/8)
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
	for j := 0; j < bob.Xi; j++ {
		betaJ := bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		if bob.beta.Get(uint(j)) != 0 {
			betaJ = bob.Protocol.Curve().ScalarField().MultiplicativeIdentity()
		}
		b = b.Add(betaJ.Mul(bob.g[j]))
	}

	return r2Out, b, nil
}

func (alice *Alice) Round3(r2Out *Round2P2P, a []curves.Scalar) (r3Out *Round3P2P, c []curves.Scalar, err error) {
	senderOutput, err := alice.sender.Round3(r2Out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot send round 3 of receiver")
	}
	alice.alpha = senderOutput.S

	c = make([]curves.Scalar, alice.L)
	for i := range alice.L {
		c[i] = alice.Protocol.Curve().ScalarField().AdditiveIdentity()
		for j := range alice.Xi {
			c[i] = c[i].Sub(alice.g[j].Mul(alice.alpha[j][0][i]))
		}
	}

	aHat := make([]curves.Scalar, alice.Rho)
	for i := range alice.Rho {
		aHat[i], err = alice.Protocol.Curve().ScalarField().Random(alice.Prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot get random scalar")
		}
	}

	aTilde := make([][]curves.Scalar, alice.Xi)
	for j := range alice.Xi {
		aTilde[j] = make([]curves.Scalar, alice.L+alice.Rho)
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

	eta := make([]curves.Scalar, alice.Rho)
	for k := range alice.Rho {
		eta[k] = aHat[k]
		for i := range alice.L {
			eta[k] = eta[k].Add(theta[i][k].Mul(a[i]))
		}
	}

	muBold := make([][]curves.Scalar, alice.Xi)
	for j := range alice.Xi {
		muBold[j] = make([]curves.Scalar, alice.Rho)
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

	r3Out = &Round3P2P{
		ATilde: aTilde,
		Eta:    eta,
		Mu:     mu,
	}
	return r3Out, c, nil
}

func (bob *Bob) Round4(r3Out *Round3P2P) (d []curves.Scalar, err error) {
	theta, err := bob.roTheta(r3Out.ATilde)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get theta")
	}

	dDot := make([][]curves.Scalar, bob.Xi)
	for j := range bob.Xi {
		dDot[j] = make([]curves.Scalar, bob.L)
		betaJ := bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		if bob.beta.Get(uint(j)) != 0 {
			betaJ = bob.Protocol.Curve().ScalarField().MultiplicativeIdentity()
		}
		for i := range bob.L {
			dDot[j][i] = bob.gamma[j][i].Add(betaJ.Mul(r3Out.ATilde[j][i]))
		}
	}

	dHat := make([][]curves.Scalar, bob.Xi)
	for j := range bob.Xi {
		dHat[j] = make([]curves.Scalar, bob.Rho)
		betaJ := bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		if bob.beta.Get(uint(j)) != 0 {
			betaJ = bob.Protocol.Curve().ScalarField().MultiplicativeIdentity()
		}
		for k := range bob.Rho {
			dHat[j][k] = bob.gamma[j][bob.L+k].Add(betaJ.Mul(r3Out.ATilde[j][bob.L+k]))
		}
	}

	muPrimeBold := make([][]curves.Scalar, bob.Xi)
	for j := range bob.Xi {
		muPrimeBold[j] = make([]curves.Scalar, bob.Rho)
		betaJ := bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		if bob.beta.Get(uint(j)) != 0 {
			betaJ = bob.Protocol.Curve().ScalarField().MultiplicativeIdentity()
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

	d = make([]curves.Scalar, bob.L)
	for i := range bob.L {
		d[i] = bob.Protocol.Curve().ScalarField().AdditiveIdentity()
		for j := range bob.Xi {
			d[i] = d[i].Add(bob.g[j].Mul(dDot[j][i]))
		}
	}

	return d, nil
}

func (p *participant) roTheta(aTilde [][]curves.Scalar) (theta [][]curves.Scalar, err error) {
	for _, aTildeJ := range aTilde {
		p.Tape.AppendScalars(aTildeLabel, aTildeJ...)
	}

	theta = make([][]curves.Scalar, p.L)
	for i := range theta {
		theta[i] = make([]curves.Scalar, p.Rho)
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
