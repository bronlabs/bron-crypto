package rvole_softspoken

import (
	"bytes"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// Round1 executes protocol round 1.
func (bob *Bob[P, B, S]) Round1() (r1 *Round1P2P, b S, err error) {
	var nilS S
	if bob.round != 1 {
		return nil, nilS, ErrValidation.WithMessage("invalid round")
	}

	beta := make([]byte, bob.xi/8)
	if _, err := io.ReadFull(bob.prng, beta); err != nil {
		return nil, nilS, errs.Wrap(err).WithMessage("cannot sample choices")
	}

	r1, receiverOutput, err := bob.receiver.Round1(beta)
	if err != nil {
		return nil, nilS, errs.Wrap(err).WithMessage("cannot run round 2 of receiver")
	}
	bob.beta = receiverOutput.Choices
	bob.gamma = make([][]S, len(receiverOutput.Messages))
	for xi, messages := range receiverOutput.Messages {
		bob.gamma[xi] = make([]S, len(messages))
		for l, message := range messages {
			bob.gamma[xi][l], err = bob.suite.field.Hash(message)
			if err != nil {
				return nil, nilS, errs.Wrap(err).WithMessage("cannot hash to curve message")
			}
		}
	}

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
	return r1, b, nil
}

// Round2 executes protocol round 2.
func (alice *Alice[P, B, S]) Round2(r1 *Round1P2P, a []S) (*Round2P2P[S], []S, error) {
	if alice.round != 2 {
		return nil, nil, ErrValidation.WithMessage("invalid round")
	}

	senderOutput, err := alice.sender.Round2(r1)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run round 2 of receiver")
	}
	alice.alpha = make([][2][]S, len(senderOutput.Messages))
	for xi, messages := range senderOutput.Messages {
		alice.alpha[xi][0] = make([]S, len(messages[0]))
		alice.alpha[xi][1] = make([]S, len(messages[1]))
		for l, message := range messages[0] {
			alice.alpha[xi][0][l], err = alice.suite.field.Hash(message)
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot hash to field message")
			}
		}
		for l, message := range messages[1] {
			alice.alpha[xi][1][l], err = alice.suite.field.Hash(message)
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot hash to field message")
			}
		}
	}

	c := make([]S, alice.suite.l)
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
			return nil, nil, errs.Wrap(err).WithMessage("cannot get random scalar")
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
		return nil, nil, errs.Wrap(err).WithMessage("cannot get theta")
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
		return nil, nil, errs.Wrap(err).WithMessage("cannot get mu")
	}

	r2 := &Round2P2P[S]{
		ATilde: aTilde,
		Eta:    eta,
		Mu:     mu,
	}
	alice.round += 2
	return r2, c, nil
}

// Round3 executes protocol round 3.
func (bob *Bob[P, B, S]) Round3(r2 *Round2P2P[S]) (d []S, err error) {
	if bob.round != 3 {
		return nil, ErrValidation.WithMessage("invalid round")
	}
	if err := r2.Validate(bob.xi, bob.suite.l, bob.rho); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid message")
	}

	theta, err := bob.roTheta(r2.ATilde)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get theta")
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
			dDot[j][i] = bob.gamma[j][i].Add(betaJ.Mul(r2.ATilde[j][i]))
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
			dHat[j][k] = bob.gamma[j][bob.suite.l+k].Add(betaJ.Mul(r2.ATilde[j][bob.suite.l+k]))
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
			muPrimeBold[j][k] = dHat[j][k].Sub(betaJ.Mul(r2.Eta[k]))
			for i := range bob.suite.l {
				muPrimeBold[j][k] = muPrimeBold[j][k].Add(theta[i][k].Mul(dDot[j][i]))
			}
		}
	}

	mu, err := bob.roMu(muPrimeBold)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get mu")
	}
	if !bytes.Equal(r2.Mu, mu) {
		return nil, base.ErrAbort.WithMessage("consistency check failed")
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

func (p *participant[P, B, S]) roTheta(aTilde [][]S) (theta [][]S, err error) {
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
				return nil, errs.Wrap(err).WithMessage("cannot extract theta")
			}
			theta[i][j], err = p.suite.field.FromWideBytes(thetaBytes)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot set theta")
			}
		}
	}

	return theta, nil
}

func (p *participant[P, B, S]) roMu(muBold [][]S) (mu []byte, err error) {
	for _, muJ := range muBold {
		for _, e := range muJ {
			p.tape.AppendBytes(muVectorLabel, e.Bytes())
		}
	}
	mu, err = p.tape.ExtractBytes(muLabel, base.CollisionResistanceBytesCeil)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract mu")
	}
	return mu, nil
}
