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
	sid         []byte
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

	return &VerifierRound1Output{
		esidCommitment: esidCommitment,
	}, nil
}

func (prover *Prover) Round2(input *VerifierRound1Output) (output *ProverRound2Output, err error) {
	prover.state.esidCommitment = input.esidCommitment

	prover.state.w1 = make([]*big.Int, prover.t)
	prover.state.w2 = make([]*big.Int, prover.t)
	for i := 0; i < prover.t; i++ {
		flip, err := crand.Int(prover.prng, big.NewInt(2))
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create random")
		}
		if flip.Cmp(big.NewInt(1)) == 0 {
			prover.state.w2[i], err = crand.Int(prover.prng, prover.state.l)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot create random")
			}
			prover.state.w1[i] = new(big.Int).Sub(prover.state.w2[i], prover.state.l)
		} else {
			prover.state.w1[i], err = crand.Int(prover.prng, prover.state.l)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot create random")
			}
			prover.state.w2[i] = new(big.Int).Sub(prover.state.w2[i], prover.state.l)
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

	return &ProverRound2Output{
		c1: c1,
		c2: c2,
	}, nil
}

func (verifier *Verifier) Round3(input *ProverRound2Output) (output *VerifierRound3Output, err error) {
	verifier.state.c1 = input.c1
	verifier.state.c2 = input.c2

	return &VerifierRound3Output{
		e:           verifier.state.e,
		sid:         verifier.sid,
		esidWitness: verifier.state.esidWitness,
	}, nil
}

func (prover *Prover) Round4(input *VerifierRound3Output) (output *ProverRound4Output, err error) {
	esidMessage := append(input.e.Bytes()[:], input.sid...)
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
			xPlusW1 := new(big.Int).Add(prover.x.BigInt(), prover.state.w1[i])
			xPlusW2 := new(big.Int).Add(prover.x.BigInt(), prover.state.w2[i])
			if xPlusW1.Cmp(prover.state.l) >= 0 && xPlusW1.Cmp(new(big.Int).Add(prover.state.l, prover.state.l)) <= 0 {
				zetOne[i] = &ZetOne{
					j:        1,
					xPlusWj:  xPlusW1,
					rTimesRj: new(big.Int).Mod(new(big.Int).Mul(prover.r, prover.state.r1[i]), prover.sk.N),
				}
			} else if xPlusW2.Cmp(prover.state.l) >= 0 && xPlusW2.Cmp(new(big.Int).Add(prover.state.l, prover.state.l)) <= 0 {
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

	return &ProverRound4Output{
		zetZero: zetZero,
		zetOne:  zetOne,
	}, nil
}

func (verifier *Verifier) Round5(input *ProverRound4Output) (err error) {
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
			if (z.w1.Cmp(verifier.state.l) >= 0 &&
				z.w1.Cmp(new(big.Int).Add(verifier.state.l, verifier.state.l)) <= 0 &&
				z.w2.Cmp(big.NewInt(0)) >= 0 &&
				z.w2.Cmp(verifier.state.l) <= 0) || (z.w2.Cmp(verifier.state.l) >= 0 &&
				z.w2.Cmp(new(big.Int).Add(verifier.state.l, verifier.state.l)) <= 0 &&
				z.w1.Cmp(big.NewInt(0)) >= 0 &&
				z.w1.Cmp(verifier.state.l) <= 0) {
				continue
			}
			return errs.NewVerificationFailed("failed")
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

			if (*cCheck).Cmp(c) != 0 {
				return errs.NewVerificationFailed("failed")
			}
			if (*wi).Cmp(verifier.state.l) < 0 || (*wi).Cmp(new(big.Int).Add(verifier.state.l, verifier.state.l)) > 0 {
				return errs.NewVerificationFailed("failed")
			}
		}
	}

	return nil
}
