package paillierrange

import (
	crand "crypto/rand"
	"io"
	"math/big"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

const Name sigma.Name = "ZKPOK_PAILLIER_RANGE"

type Statement struct {
	PaillierPublicKey *paillier.PublicKey
	CipherText        *paillier.CipherText
}

var _ sigma.Statement = (*Statement)(nil)

type Witness struct {
	PaillierSecretKey *paillier.SecretKey
	PlainText         *saferith.Nat
	Nonce             *saferith.Nat
}

var _ sigma.Witness = (*Witness)(nil)

type Commitment struct {
	C1 []*paillier.CipherText
	C2 []*paillier.CipherText
}

var _ sigma.Commitment = (*Commitment)(nil)

type State struct {
	W1 []*saferith.Nat
	R1 []*saferith.Nat
	W2 []*saferith.Nat
	R2 []*saferith.Nat
}

var _ sigma.State = (*State)(nil)

type ResponseZero struct {
	W1 *saferith.Nat
	R1 *saferith.Nat
	W2 *saferith.Nat
	R2 *saferith.Nat
}

type ResponseOne struct {
	J        int
	XPlusWj  *saferith.Nat
	RTimesRj *saferith.Nat
}

type Response struct {
	Z0 []*ResponseZero
	Z1 []*ResponseOne
}

var _ sigma.Response = (*Response)(nil)

type protocol struct {
	t    int
	l    *saferith.Nat
	q    *saferith.Nat
	prng io.Reader
}

var _ sigma.Protocol[*Statement, *Witness, *Commitment, *State, *Response] = (*protocol)(nil)

func NewSigmaProtocol(t int, q *saferith.Nat, prng io.Reader) sigma.Protocol[*Statement, *Witness, *Commitment, *State, *Response] {
	// 2.i. computes l = ceil(q/3)
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), -1)

	return &protocol{
		t:    t,
		l:    l,
		q:    q,
		prng: prng,
	}
}

func (*protocol) Name() sigma.Name {
	return Name
}

func (p *protocol) ComputeProverCommitment(_ *Statement, witness *Witness) (*Commitment, *State, error) {
	s := &State{
		W1: make([]*saferith.Nat, p.t),
		R1: make([]*saferith.Nat, p.t),
		W2: make([]*saferith.Nat, p.t),
		R2: make([]*saferith.Nat, p.t),
	}

	flip, err := crand.Int(p.prng, new(big.Int).Lsh(big.NewInt(1), uint(p.t)))
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "random sample failed")
	}
	for i := 0; i < p.t; i++ {
		choice := flip.Bit(i)

		// 2.iii. choose random w1i (in 0-l range), w2i (in l-2l range)
		// 2.iv. flip value of w1i and w2i with 0.5 probability
		if choice == 0 {
			s.W2[i], err = p.randomIntInFirstThird()
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot create random")
			}
			s.W1[i] = new(saferith.Nat).Add(s.W2[i], p.l, -1)
		} else {
			s.W1[i], err = p.randomIntInFirstThird()
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot create random")
			}
			s.W2[i] = new(saferith.Nat).Add(s.W1[i], p.l, -1)
		}
	}

	// 2.v. computes c1i = Enc(w1i, r1i) and c2i = Enc(w2i, r2i)
	a := &Commitment{
		C1: make([]*paillier.CipherText, p.t),
		C2: make([]*paillier.CipherText, p.t),
	}
	for i := 0; i < p.t; i++ {
		a.C1[i], s.R1[i], err = witness.PaillierSecretKey.Encrypt(s.W1[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot encrypt")
		}
		a.C2[i], s.R2[i], err = witness.PaillierSecretKey.Encrypt(s.W2[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot encrypt")
		}
	}

	return a, s, nil
}

func (p *protocol) ComputeProverResponse(_ *Statement, witness *Witness, _ *Commitment, state *State, challenge sigma.ChallengeBytes) (*Response, error) {
	zetZero := make([]*ResponseZero, p.t)
	zetOne := make([]*ResponseOne, p.t)

	// 4. for every i
	e := new(big.Int).SetBytes(challenge)
	for i := 0; i < p.t; i++ {
		if e.Bit(i) == 0 {
			// 4.i. if ei == 0 set zi = (w1i, r1i, w2i, r2i)
			zetZero[i] = &ResponseZero{
				W1: state.W1[i],
				R1: state.R1[i],
				W2: state.W2[i],
				R2: state.R2[i],
			}
		} else {
			// 4.ii. if ei == 1
			xPlusW1 := new(saferith.Nat).Add(witness.PlainText, state.W1[i], -1)
			xPlusW2 := new(saferith.Nat).Add(witness.PlainText, state.W2[i], -1)
			switch {
			case p.inSecondThird(xPlusW1):
				// 4.ii. if (x + w1) in l-2l range set zi = (1, x + w1i, r * r1i mod N)
				zetOne[i] = &ResponseOne{
					J:        1,
					XPlusWj:  xPlusW1,
					RTimesRj: new(saferith.Nat).ModMul(witness.Nonce, state.R1[i], witness.PaillierSecretKey.PublicKey.N),
				}
			case p.inSecondThird(xPlusW2):
				// 4.ii. if (x + w2) in l-2l range set zi = (2, x + w2i, r * r2i mod N)
				zetOne[i] = &ResponseOne{
					J:        2,
					XPlusWj:  xPlusW2,
					RTimesRj: new(saferith.Nat).ModMul(witness.Nonce, state.R2[i], witness.PaillierSecretKey.PublicKey.N),
				}
			default:
				return nil, errs.NewFailed("something went wrong")
			}
		}
	}

	return &Response{
		Z0: zetZero,
		Z1: zetOne,
	}, nil
}

func (p *protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	e := new(big.Int).SetBytes(challenge)

	for i := 0; i < p.t; i++ {
		if e.Bit(i) == 0 {
			// 5.i. if ei == 0 check c1i == Enc(w1i, r1i) and c2i == Enc(w2i, r2i)
			// and one of w1i, w2i is in l-2l range while other is in 0-l range
			z := response.Z0[i]
			if z == nil {
				return errs.NewVerification("verification failed")
			}

			c1, err := statement.PaillierPublicKey.EncryptWithNonce(z.W1, z.R1)
			if err != nil {
				return errs.WrapFailed(err, "cannot encrypt")
			}
			if c1.C.Eq(commitment.C1[i].C) != 1 {
				return errs.NewVerification("verification failed")
			}

			c2, err := statement.PaillierPublicKey.EncryptWithNonce(z.W2, z.R2)
			if err != nil {
				return errs.WrapFailed(err, "cannot encrypt")
			}
			if c2.C.Eq(commitment.C2[i].C) != 1 {
				return errs.NewVerification("verification failed")
			}
			if !((p.inFirstThird(z.W1) && p.inSecondThird(z.W2)) ||
				(p.inFirstThird(z.W2) && p.inSecondThird(z.W1))) {

				return errs.NewVerification("verification failed")
			}
		} else {
			// 5.ii if ei == 1 check that c (+) cji == Enc(wi, ri) and wi in range l-2l
			// where zi = (j, wi, ri)
			z := response.Z1[i]
			if z == nil {
				return errs.NewVerification("verification failed")
			}

			wi := z.XPlusWj
			ri := z.RTimesRj
			cCheck, err := statement.PaillierPublicKey.EncryptWithNonce(wi, ri)
			if err != nil {
				return errs.WrapFailed(err, "cannot encrypt")
			}
			var c *paillier.CipherText
			if z.J == 1 {
				c, err = statement.PaillierPublicKey.Add(statement.CipherText, commitment.C1[i])
				if err != nil {
					return errs.WrapFailed(err, "cannot homomorphically add")
				}
			} else if z.J == 2 {
				c, err = statement.PaillierPublicKey.Add(statement.CipherText, commitment.C2[i])
				if err != nil {
					return errs.WrapFailed(err, "cannot homomorphically add")
				}
			}

			if cCheck.C.Eq(c.C) != 1 || !p.inSecondThird(wi) {
				return errs.NewVerification("verification failed")
			}
		}
	}

	return nil
}

func (p *protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	c1 := make([]*paillier.CipherText, p.t)
	c2 := make([]*paillier.CipherText, p.t)
	zetZero := make([]*ResponseZero, p.t)
	zetOne := make([]*ResponseOne, p.t)

	e := new(big.Int).SetBytes(challenge)
	flip, err := crand.Int(p.prng, new(big.Int).Lsh(big.NewInt(1), uint(p.t)))
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "random sample failed")
	}
	for i := 0; i < p.t; i++ {
		if e.Bit(i) == 0 {
			w2, err := p.randomIntInFirstThird()
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot create random")
			}
			var r2 *saferith.Nat
			c2[i], r2, err = statement.PaillierPublicKey.Encrypt(w2)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot encrypt")
			}
			w1 := new(saferith.Nat).Add(w2, p.l, -1)
			var r1 *saferith.Nat
			c1[i], r1, err = statement.PaillierPublicKey.Encrypt(w1)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot encrypt")
			}

			zetZero[i] = &ResponseZero{
				W1: w1,
				R1: r1,
				W2: w2,
				R2: r2,
			}
		}

		if e.Bit(i) == 1 {
			wPrime, err := p.randomIntInFirstThird()
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot compute w")
			}
			w := new(saferith.Nat).Add(wPrime, p.l, -1)
			cPrime, r, err := statement.PaillierPublicKey.Encrypt(w)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot compute enc(w)")
			}
			c, err := statement.PaillierPublicKey.Sub(cPrime, statement.CipherText)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot compute enc(w) - c")
			}
			zero, err := statement.PaillierPublicKey.EncryptWithNonce(new(saferith.Nat).SetUint64(0), r)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot compute enc(0)")
			}

			j := flip.Bit(i)
			if j == 0 {
				c1[i] = c
				c2[i] = zero
			}
			if j == 1 {
				c2[i] = c
				c1[i] = zero
			}

			zetOne[i] = &ResponseOne{
				J:        int(j + 1),
				XPlusWj:  w,
				RTimesRj: r,
			}
		}
	}

	a := &Commitment{
		C1: c1,
		C2: c2,
	}
	z := &Response{
		Z0: zetZero,
		Z1: zetOne,
	}

	return a, z, nil
}

func (p *protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	decryptor, err := paillier.NewDecryptor(witness.PaillierSecretKey)
	if err != nil {
		return errs.WrapFailed(err, "cannot create decryptor")
	}

	plain, err := decryptor.Decrypt(statement.CipherText)
	if err != nil {
		return errs.WrapFailed(err, "cannot decrypt cipher text")
	}

	if plain.Eq(witness.PlainText) != 1 {
		return errs.NewValidation("invalid statement")
	}

	_, _, less := plain.Cmp(p.q)
	if less != 1 {
		return errs.NewValidation("invalid statement")
	}

	return nil
}

func (p *protocol) GetChallengeBytesLength() int {
	return (p.t + 7) / 8
}

func (*protocol) SerializeStatement(statement *Statement) []byte {
	return slices.Concat(statement.CipherText.C.Bytes(), statement.PaillierPublicKey.N.Bytes())
}

func (p *protocol) SerializeCommitment(commitment *Commitment) []byte {
	serialised := make([]byte, 0)
	for i := 0; i < p.t; i++ {
		serialised = append(serialised, commitment.C1[i].C.Bytes()...)
		serialised = append(serialised, commitment.C2[i].C.Bytes()...)
	}

	return serialised
}

func (p *protocol) SerializeResponse(response *Response) []byte {
	serialised := make([]byte, 0)
	for i := 0; i < p.t; i++ {
		if response.Z0[i] != nil {
			serialised = append(serialised, response.Z0[i].W1.Bytes()...)
			serialised = append(serialised, response.Z0[i].R1.Bytes()...)
			serialised = append(serialised, response.Z0[i].W2.Bytes()...)
			serialised = append(serialised, response.Z0[i].R2.Bytes()...)
		}
		if response.Z1[i] != nil {
			serialised = append(serialised, bitstring.ToBytesLE(response.Z1[i].J)...)
			serialised = append(serialised, response.Z1[i].XPlusWj.Bytes()...)
			serialised = append(serialised, response.Z1[i].RTimesRj.Bytes()...)
		}
	}

	return serialised
}

func (p *protocol) randomIntInFirstThird() (*saferith.Nat, error) {
	natBig, err := crand.Int(p.prng, p.l.Big())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed")
	}
	return new(saferith.Nat).SetBig(natBig, natBig.BitLen()), nil
}

func (p *protocol) inFirstThird(x *saferith.Nat) bool {
	_, _, less := x.Cmp(p.l)
	return less == 1
}

func (p *protocol) inSecondThird(x *saferith.Nat) bool {
	twoL := new(saferith.Nat).Lsh(p.l, 1, -1)
	_, _, lessThanTwoL := x.Cmp(twoL)
	_, _, lessThanL := x.Cmp(p.l)

	return (lessThanTwoL & (lessThanL ^ 1)) == 1
}
