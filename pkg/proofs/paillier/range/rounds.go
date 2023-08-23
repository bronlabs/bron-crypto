package paillierrange

import (
	crand "crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
)

var hashFunc = sha256.New

type Round1Output struct {
	EsidCommitment commitments.Commitment

	_ helper_types.Incomparable
}

type ProverRound2Output struct {
	C1 []paillier.CipherText
	C2 []paillier.CipherText

	_ helper_types.Incomparable
}

type VerifierRound3Output struct {
	E           *big.Int
	EsidWitness commitments.Witness

	_ helper_types.Incomparable
}

type ZetZero struct {
	W1 *saferith.Nat
	R1 *saferith.Nat
	W2 *saferith.Nat
	R2 *saferith.Nat

	_ helper_types.Incomparable
}

type ZetOne struct {
	J        int
	XPlusWj  *saferith.Nat
	RTimesRj *saferith.Nat

	_ helper_types.Incomparable
}

type Round4Output struct {
	ZetZero []*ZetZero
	ZetOne  []*ZetOne

	_ helper_types.Incomparable
}

func (verifier *Verifier) Round1() (output *Round1Output, err error) {
	if verifier.round != 1 {
		return nil, errs.NewInvalidRound("%d != 1", verifier.round)
	}

	// 1.iii. chooses a random e (t bit length)
	// this values is used to iterate over bits - more convenient to keep as big.Int
	verifier.state.e, err = crand.Int(verifier.prng, new(big.Int).Lsh(big.NewInt(1), uint(verifier.t)))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get random number")
	}

	// 1.iv. compute commitment to (e, sid) and send to P
	esidMessage := append(verifier.state.e.Bytes(), verifier.sid...)
	esidCommitment, esidWitness, err := commitments.Commit(hashFunc, esidMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to e, sid")
	}
	verifier.state.esidWitness = esidWitness

	verifier.round += 2
	return &Round1Output{
		EsidCommitment: esidCommitment,
	}, nil
}

func (prover *Prover) Round2(input *Round1Output) (output *ProverRound2Output, err error) {
	if prover.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", prover.round)
	}

	prover.state.esidCommitment = input.EsidCommitment
	prover.state.w1 = make([]*saferith.Nat, prover.t)
	prover.state.w2 = make([]*saferith.Nat, prover.t)
	for i := 0; i < prover.t; i++ {
		flip := make([]byte, 1)
		_, err = prover.prng.Read(flip)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create random")
		}

		// 2.iii. choose random w1i (in 0-l range), w2i (in l-2l range)
		// 2.iv. flip value of w1i and w2i with 0.5 probability
		if flip[0]&1 == 0 {
			prover.state.w2[i], err = prover.randomIntInFirstThird()
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot create random")
			}
			prover.state.w1[i] = new(saferith.Nat).Add(prover.state.w2[i], prover.l, prover.capLen)
		} else {
			prover.state.w1[i], err = prover.randomIntInFirstThird()
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot create random")
			}
			prover.state.w2[i] = new(saferith.Nat).Add(prover.state.w1[i], prover.l, prover.capLen)
		}
	}

	// 2.v. computes c1i = Enc(w1i, r1i) and c2i = Enc(w2i, r2i)
	prover.state.r1 = make([]*saferith.Nat, prover.t)
	prover.state.r2 = make([]*saferith.Nat, prover.t)
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

	// 2.vi. send c1i, c2i to V
	prover.round += 2
	return &ProverRound2Output{
		C1: c1,
		C2: c2,
	}, nil
}

func (verifier *Verifier) Round3(input *ProverRound2Output) (output *VerifierRound3Output, err error) {
	if verifier.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", verifier.round)
	}

	verifier.state.c1 = input.C1
	verifier.state.c2 = input.C2

	verifier.round += 2

	// 3. decommit (e, sid), reveal (e, sid) to P
	return &VerifierRound3Output{
		E:           verifier.state.e,
		EsidWitness: verifier.state.esidWitness,
	}, nil
}

func (prover *Prover) Round4(input *VerifierRound3Output) (output *Round4Output, err error) {
	if prover.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", prover.round)
	}

	esidMessage := append(input.E.Bytes(), prover.sid...)
	err = commitments.Open(hashFunc, esidMessage, prover.state.esidCommitment, input.EsidWitness)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot open commitment")
	}

	// 4. for every i
	zetZero := make([]*ZetZero, prover.t)
	zetOne := make([]*ZetOne, prover.t)
	for i := 0; i < prover.t; i++ {
		if input.E.Bit(i) == 0 {
			// 4.i. if ei == 0 set zi = (w1i, r1i, w2i, r2i)
			zetZero[i] = &ZetZero{
				W1: prover.state.w1[i],
				R1: prover.state.r1[i],
				W2: prover.state.w2[i],
				R2: prover.state.r2[i],
			}
		} else {
			// 4.ii. if ei == 1
			xPlusW1 := new(saferith.Nat).Add(prover.x, prover.state.w1[i], prover.capLen)
			xPlusW2 := new(saferith.Nat).Add(prover.x, prover.state.w2[i], prover.capLen)
			switch {
			case prover.inSecondThird(xPlusW1):
				// 4.ii. if (x + w1) in l-2l range set zi = (1, x + w1i, r * r1i mod N)
				zetOne[i] = &ZetOne{
					J:        1,
					XPlusWj:  xPlusW1,
					RTimesRj: new(saferith.Nat).ModMul(prover.r, prover.state.r1[i], prover.sk.N),
				}
			case prover.inSecondThird(xPlusW2):
				// 4.ii. if (x + w2) in l-2l range set zi = (2, x + w2i, r * r2i mod N)
				zetOne[i] = &ZetOne{
					J:        2,
					XPlusWj:  xPlusW2,
					RTimesRj: new(saferith.Nat).ModMul(prover.r, prover.state.r2[i], prover.sk.N),
				}
			default:
				return nil, errs.NewFailed("something went wrong")
			}
		}
	}

	// 4.iii. send zi to V
	prover.round += 2
	return &Round4Output{
		ZetZero: zetZero,
		ZetOne:  zetOne,
	}, nil
}

func (verifier *Verifier) Round5(input *Round4Output) (err error) {
	if verifier.round != 5 {
		return errs.NewInvalidRound("%d != 5", verifier.round)
	}

	// 5. Parse zi
	for i := 0; i < verifier.t; i++ {
		if verifier.state.e.Bit(i) == 0 {
			// 5.i. if ei == 0 check c1i == Enc(w1i, r1i) and c2i == Enc(w2i, r2i)
			// and one of w1i, w2i is in l-2l range while other is in 0-l range
			z := input.ZetZero[i]
			c1, err := verifier.pk.EncryptWithNonce(z.W1, z.R1)
			if err != nil {
				return errs.WrapFailed(err, "cannot encrypt")
			}
			//nolint:gocritic // Cmp not a method of c1. False positive.
			if (*c1).Eq(verifier.state.c1[i]) == 0 {
				return errs.NewVerificationFailed("verification failed")
			}
			c2, err := verifier.pk.EncryptWithNonce(z.W2, z.R2)
			if err != nil {
				return errs.WrapFailed(err, "cannot encrypt")
			}
			//nolint:gocritic // Cmp not a method of c2. False positive.
			if (*c2).Eq(verifier.state.c2[i]) == 0 {
				return errs.NewVerificationFailed("verification failed")
			}
			if !((verifier.inFirstThird(z.W1) && verifier.inSecondThird(z.W2)) ||
				(verifier.inFirstThird(z.W2) && verifier.inSecondThird(z.W1))) {

				return errs.NewVerificationFailed("verification failed")
			}
		} else {
			// 5.ii if ei == 1 check that c (+) cji == Enc(wi, ri) and wi in range l-2l
			// where zi = (j, wi, ri)
			z := input.ZetOne[i]
			wi := z.XPlusWj
			ri := z.RTimesRj
			cCheck, err := verifier.pk.EncryptWithNonce(wi, ri)
			if err != nil {
				return errs.WrapFailed(err, "cannot encrypt")
			}
			var c paillier.CipherText
			if z.J == 1 {
				c, err = verifier.pk.Add(verifier.c, verifier.state.c1[i])
				if err != nil {
					return errs.WrapFailed(err, "cannot homomorphically add")
				}
			} else if z.J == 2 {
				c, err = verifier.pk.Add(verifier.c, verifier.state.c2[i])
				if err != nil {
					return errs.WrapFailed(err, "cannot homomorphically add")
				}
			}

			//nolint:gocritic // Cmp not a method of cCheck. False positive.
			if (*cCheck).Eq(c) == 0 || !verifier.inSecondThird(wi) {
				return errs.NewVerificationFailed("verification failed")
			}
		}
	}

	verifier.round += 2
	return nil
}

func (p *Participant) inFirstThird(v *saferith.Nat) bool {
	if _, ok1, ok2 := v.Cmp(p.l); (ok1 | ok2) != 0 {
		return true
	}

	return false
}

func (p *Participant) inSecondThird(v *saferith.Nat) bool {
	v2 := new(saferith.Nat).Sub(v, p.l, p.capLen)
	return p.inFirstThird(v2)
}

func (p *Participant) randomIntInFirstThird() (*saferith.Nat, error) {
	nInt, err := crand.Int(p.prng, p.l.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "reading crand int failed")
	}
	n := new(saferith.Nat).SetBig(nInt, p.capLen)
	return n, nil
}
