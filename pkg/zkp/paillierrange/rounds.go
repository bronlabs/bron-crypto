package paillierrange

import (
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"math/big"
)

var (
	hashFunc = sha256.New
)

type VerifierRound1Output struct {
	esidCommitment commitments.Commitment
}

type ProverRound2Output struct {
	c1 []paillier.CipherText
	c2 []paillier.CipherText
}

type VerifierRound3Output struct {
	e           *big.Int
	esidWitness commitments.Witness
}

type ZetZero struct {
	w1 *big.Int
	r1 *big.Int
	w2 *big.Int
	r2 *big.Int
}

type ZetOne struct {
	j        int
	xPlusWj  *big.Int
	rTimesRj *big.Int
}

type ProverRound4Output struct {
	zetZero []*ZetZero
	zetOne  []*ZetOne
}

func (verifier *Verifier) Round1() (output *VerifierRound1Output, err error) {
	if verifier.round != 1 {
		return nil, errs.NewInvalidRound("%d != 1", verifier.round)
	}

	verifier.state.e, err = crand.Int(verifier.prng, new(big.Int).Lsh(big.NewInt(1), uint(verifier.t)))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get random number")
	}

	esidMessage := append(verifier.state.e.Bytes()[:], verifier.sid...)
	esidCommitment, esidWitness, err := commitments.Commit(hashFunc, esidMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to e, sid")
	}
	verifier.state.esidWitness = esidWitness

	verifier.round += 2
	return &VerifierRound1Output{
		esidCommitment: esidCommitment,
	}, nil
}

func (prover *Prover) Round2(input *VerifierRound1Output) (output *ProverRound2Output, err error) {
	if prover.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", prover.round)
	}

	prover.state.esidCommitment = input.esidCommitment
	prover.state.w1 = make([]*big.Int, prover.t)
	prover.state.w2 = make([]*big.Int, prover.t)
	for i := 0; i < prover.t; i++ {
		flip, err := crand.Int(prover.prng, big.NewInt(2))
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create random")
		}

		if flip.Cmp(big.NewInt(1)) == 0 {
			prover.state.w2[i], err = prover.randomIntInFirstThird()
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot create random")
			}
			prover.state.w1[i] = new(big.Int).Add(prover.state.w2[i], prover.l)
		} else {
			prover.state.w1[i], err = prover.randomIntInFirstThird()
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot create random")
			}
			prover.state.w2[i] = new(big.Int).Add(prover.state.w1[i], prover.l)
		}
	}

	prover.state.r1 = make([]*big.Int, prover.t)
	prover.state.r2 = make([]*big.Int, prover.t)
	c1 := make([]paillier.CipherText, prover.t)
	c2 := make([]paillier.CipherText, prover.t)
	for i := 0; i < prover.t; i++ {
		c1[i], prover.state.r1[i], err = prover.sk.Encrypt(prover.state.w1[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot encrypt")
		}
		c2[i], prover.state.r2[i], err = prover.sk.Encrypt(prover.state.w2[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot encrypt")
		}
	}

	prover.round += 2
	return &ProverRound2Output{
		c1: c1,
		c2: c2,
	}, nil
}

func (verifier *Verifier) Round3(input *ProverRound2Output) (output *VerifierRound3Output, err error) {
	if verifier.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", verifier.round)
	}

	verifier.state.c1 = input.c1
	verifier.state.c2 = input.c2

	verifier.round += 2
	return &VerifierRound3Output{
		e:           verifier.state.e,
		esidWitness: verifier.state.esidWitness,
	}, nil
}

func (prover *Prover) Round4(input *VerifierRound3Output) (output *ProverRound4Output, err error) {
	if prover.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", prover.round)
	}

	esidMessage := append(input.e.Bytes()[:], prover.sid...)
	err = commitments.Open(hashFunc, esidMessage, prover.state.esidCommitment, input.esidWitness)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot open commitment")
	}

	zetZero := make([]*ZetZero, prover.t)
	zetOne := make([]*ZetOne, prover.t)
	for i := 0; i < prover.t; i++ {
		if input.e.Bit(i) == 0 {
			zetZero[i] = &ZetZero{
				w1: prover.state.w1[i],
				r1: prover.state.r1[i],
				w2: prover.state.w2[i],
				r2: prover.state.r2[i],
			}
		} else {
			xPlusW1 := new(big.Int).Add(prover.x, prover.state.w1[i])
			xPlusW2 := new(big.Int).Add(prover.x, prover.state.w2[i])
			if prover.inSecondThird(xPlusW1) {
				zetOne[i] = &ZetOne{
					j:        1,
					xPlusWj:  xPlusW1,
					rTimesRj: new(big.Int).Mod(new(big.Int).Mul(prover.r, prover.state.r1[i]), prover.sk.N),
				}
			} else if prover.inSecondThird(xPlusW2) {
				zetOne[i] = &ZetOne{
					j:        2,
					xPlusWj:  xPlusW2,
					rTimesRj: new(big.Int).Mod(new(big.Int).Mul(prover.r, prover.state.r2[i]), prover.sk.N),
				}
			} else {
				return nil, errs.NewFailed("something went wrong")
			}
		}
	}

	prover.round += 2
	return &ProverRound4Output{
		zetZero: zetZero,
		zetOne:  zetOne,
	}, nil
}

func (verifier *Verifier) Round5(input *ProverRound4Output) (err error) {
	if verifier.round != 5 {
		return errs.NewInvalidRound("%d != 5", verifier.round)
	}

	for i := 0; i < verifier.t; i++ {
		if verifier.state.e.Bit(i) == 0 {
			z := input.zetZero[i]
			c1, err := verifier.pk.EncryptWithNonce(z.w1, z.r1)
			if err != nil {
				return errs.WrapFailed(err, "cannot encrypt")
			}
			if (*c1).Cmp(verifier.state.c1[i]) != 0 {
				return errs.NewVerificationFailed("fail")
			}
			c2, err := verifier.pk.EncryptWithNonce(z.w2, z.r2)
			if err != nil {
				return errs.WrapFailed(err, "cannot encrypt")
			}
			if (*c2).Cmp(verifier.state.c2[i]) != 0 {
				return errs.NewVerificationFailed("failed")
			}
			if !((verifier.inFirstThird(z.w1) && verifier.inSecondThird(z.w2)) ||
				(verifier.inFirstThird(z.w2) && verifier.inSecondThird(z.w1))) {
				return errs.NewVerificationFailed("failed")
			}
		} else {
			z := input.zetOne[i]
			wi := z.xPlusWj
			ri := z.rTimesRj
			cCheck, err := verifier.pk.EncryptWithNonce(wi, ri)
			if err != nil {
				return errs.WrapFailed(err, "cannot encrypt")
			}
			var c paillier.CipherText
			if z.j == 1 {
				c, err = verifier.pk.Add(verifier.c, verifier.state.c1[i])
				if err != nil {
					return errs.WrapFailed(err, "cannot homomorphically add")
				}
			} else if z.j == 2 {
				c, err = verifier.pk.Add(verifier.c, verifier.state.c2[i])
				if err != nil {
					return errs.WrapFailed(err, "cannot homomorphically add")
				}
			}

			if (*cCheck).Cmp(c) != 0 || !verifier.inSecondThird(wi) {
				return errs.NewVerificationFailed("failed")
			}
		}
	}

	verifier.round += 2
	return nil
}

func (p *Participant) inFirstThird(v *big.Int) bool {
	if v.Cmp(big.NewInt(0)) >= 0 && v.Cmp(p.l) < 0 {
		return true
	}

	return false
}

func (p *Participant) inSecondThird(v *big.Int) bool {
	v2 := new(big.Int).Sub(v, p.l)
	return p.inFirstThird(v2)
}

func (p *Participant) randomIntInFirstThird() (*big.Int, error) {
	return crand.Int(p.prng, p.l)
}

func (p *Participant) randomIntInSecondThird() (*big.Int, error) {
	v, err := p.randomIntInFirstThird()
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(v, p.l), nil
}
