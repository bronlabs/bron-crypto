package paillierrange

import (
	crand "crypto/rand"
	"io"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
)

const Name = "PaillierRange"

var (
	_ sigma.Witness                                                        = (*Witness)(nil)
	_ sigma.Statement                                                      = (*Statement)(nil)
	_ sigma.Commitment                                                     = (*Commitment)(nil)
	_ sigma.Statement                                                      = (*State)(nil)
	_ sigma.Response                                                       = (*Response)(nil)
	_ sigma.Protocol[*Statement, *Witness, *Commitment, *State, *Response] = (*PaillierRange)(nil)
)

var zero *paillier.PlainText = new(saferith.Int).SetUint64(0).Resize(0)

type Witness struct {
	Sk *paillier.SecretKey
	X  *paillier.PlainText
	R  *paillier.Nonce
}

func NewWitness(sk *paillier.SecretKey, x *paillier.PlainText, r *paillier.Nonce) *Witness {
	return &Witness{
		Sk: sk,
		X:  x,
		R:  r,
	}
}

type Statement struct {
	Pk *paillier.PublicKey
	C  *paillier.CipherText
	L  *saferith.Nat
}

func NewStatement(pk *paillier.PublicKey, c *paillier.CipherText, l *saferith.Nat) *Statement {
	return &Statement{
		Pk: pk,
		C:  c,
		L:  l,
	}
}

type Commitment struct {
	C1 []*paillier.CipherText
	C2 []*paillier.CipherText
}

type State struct {
	W1 []*paillier.PlainText
	R1 []*paillier.Nonce
	W2 []*paillier.PlainText
	R2 []*paillier.Nonce
}

type Response struct {
	W1 []*paillier.PlainText
	R1 []*paillier.Nonce
	W2 []*paillier.PlainText
	R2 []*paillier.Nonce
	Wj []*paillier.PlainText
	Rj []*paillier.Nonce
	J  []uint
}

type PaillierRange struct {
	t    uint
	prng io.Reader
}

func NewPaillierRange(t uint, prng io.Reader) (*PaillierRange, error) {
	if t < base.StatisticalSecurity {
		return nil, errs.NewValidation("insufficient statistical security")
	}
	if prng == nil {
		return nil, errs.NewIsNil("nil prng")
	}

	return &PaillierRange{
		t:    t,
		prng: prng,
	}, nil
}

func (*PaillierRange) Name() sigma.Name {
	return Name
}

func (p *PaillierRange) ComputeProverCommitment(statement *Statement, witness *Witness) (*Commitment, *State, error) {
	lowBound := new(saferith.Int).SetNat(statement.L)
	highBound, err := witness.Sk.PlainTextAdd(lowBound, lowBound)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute high bound")
	}

	swaps := make([]byte, (p.t+7)/8)
	_, err = io.ReadFull(p.prng, swaps)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot generate randomness")
	}

	w := make([]*paillier.PlainText, 2*p.t)
	for i := range p.t {
		w1i, err := randomInRange(lowBound, highBound, p.prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot compute w1i")
		}
		w2i, err := witness.Sk.PlainTextSub(w1i, lowBound)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot compute w1i")
		}
		swapBit := (swaps[i/8] >> (i % 8)) % 2
		if swapBit != 0 {
			w1i, w2i = w2i, w1i
		}

		w[i] = w1i
		w[p.t+i] = w2i
	}
	c, r, err := witness.Sk.EncryptMany(w, p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot encrypt state")
	}

	a := &Commitment{
		C1: c[:p.t],
		C2: c[p.t:],
	}
	s := &State{
		W1: w[:p.t],
		R1: r[:p.t],
		W2: w[p.t:],
		R2: r[p.t:],
	}

	return a, s, nil
}

func (p *PaillierRange) ComputeProverResponse(statement *Statement, witness *Witness, _ *Commitment, state *State, challenge sigma.ChallengeBytes) (*Response, error) {
	lowBound := new(saferith.Int).SetNat(statement.L)
	highBound, err := witness.Sk.PlainTextAdd(lowBound, lowBound)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute high bound")
	}

	z := &Response{
		W1: make([]*paillier.PlainText, p.t),
		R1: make([]*paillier.Nonce, p.t),
		W2: make([]*paillier.PlainText, p.t),
		R2: make([]*paillier.Nonce, p.t),
		Wj: make([]*paillier.PlainText, p.t),
		Rj: make([]*paillier.Nonce, p.t),
		J:  make([]uint, p.t),
	}

	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			z.W1[i] = state.W1[i]
			z.R1[i] = state.R1[i]
			z.W2[i] = state.W2[i]
			z.R2[i] = state.R2[i]

			// put some dummy value to it can be serialised
			z.Wj[i] = new(saferith.Int)
			z.Rj[i] = new(saferith.Nat)
			z.J[i] = 0
		case 1:
			xPlusW1, err := witness.Sk.PlainTextAdd(witness.X, state.W1[i])
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot compute x + wj")
			}
			if isInRange(lowBound, highBound, xPlusW1) {
				z.Wj[i] = xPlusW1
				z.Rj[i], err = witness.Sk.NonceAdd(witness.R, state.R1[i])
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot compute r * rj")
				}
				z.J[i] = 1
			} else {
				xPlusW2, err := witness.Sk.PlainTextAdd(witness.X, state.W2[i])
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot compute x + wj")
				}
				z.Wj[i] = xPlusW2
				z.Rj[i], err = witness.Sk.NonceAdd(witness.R, state.R2[i])
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot compute r * rj")
				}
				z.J[i] = 2
			}

			// put some dummy value to it can be serialised
			z.W1[i] = new(saferith.Int)
			z.R1[i] = new(saferith.Nat)
			z.W2[i] = new(saferith.Int)
			z.R2[i] = new(saferith.Nat)
		default:
			panic("this should never happen")
		}
	}

	return z, nil
}

func (p *PaillierRange) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	lowBound := new(saferith.Int).SetNat(statement.L)
	highBound, err := statement.Pk.PlainTextAdd(lowBound, lowBound)
	if err != nil {
		return errs.WrapFailed(err, "cannot compute high bound")
	}

	var c []*paillier.CipherText
	var w []*paillier.PlainText
	var r []*paillier.Nonce
	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			w1i := response.W1[i]
			w2i := response.W2[i]
			if !((isInRange(lowBound, highBound, w1i) && isInRange(zero, lowBound, w2i)) ||
				isInRange(lowBound, highBound, w2i) && isInRange(zero, lowBound, w1i)) {

				return errs.NewVerification("verification failed")
			}

			w = append(w, w1i)
			r = append(r, response.R1[i])
			c = append(c, commitment.C1[i])
			w = append(w, w2i)
			r = append(r, response.R2[i])
			c = append(c, commitment.C2[i])
		case 1:
			wi := response.Wj[i]
			if !isInRange(lowBound, highBound, wi) {
				return errs.NewVerification("verification failed")
			}

			w = append(w, wi)
			r = append(r, response.Rj[i])

			switch response.J[i] {
			case 1:
				ci, err := statement.Pk.CipherTextAdd(statement.C, commitment.C1[i])
				if err != nil {
					return errs.WrapFailed(err, "cannot compute ci")
				}
				c = append(c, ci)
			case 2:
				ci, err := statement.Pk.CipherTextAdd(statement.C, commitment.C2[i])
				if err != nil {
					return errs.WrapFailed(err, "cannot compute ci")
				}
				c = append(c, ci)
			default:
				return errs.NewVerification("verification failed")
			}
		default:
			panic("this should never happen")
		}
	}

	cCheck, err := statement.Pk.EncryptManyWithNonce(w, r)
	if err != nil {
		return errs.WrapFailed(err, "cannot compute encrypted ciphertext")
	}
	for i, ci := range c {
		if !statement.Pk.CipherTextEqual(cCheck[i], ci) {
			return errs.NewVerification("verification failed")
		}
	}

	return nil
}

func (p *PaillierRange) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	lowBound := new(saferith.Int).SetNat(statement.L)
	highBound, err := statement.Pk.PlainTextAdd(lowBound, lowBound)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute high bound")
	}

	w1 := make([]*paillier.PlainText, p.t)
	r1 := make([]*paillier.Nonce, p.t)
	c1 := make([]*paillier.CipherText, p.t)
	w2 := make([]*paillier.PlainText, p.t)
	r2 := make([]*paillier.Nonce, p.t)
	c2 := make([]*paillier.CipherText, p.t)
	wj := make([]*paillier.PlainText, p.t)
	rj := make([]*paillier.Nonce, p.t)
	j := make([]uint, p.t)

	// TODO(mkk): refactor to use EncryptMany
	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			w1[i], err = randomInRange(lowBound, highBound, p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot compute w1i")
			}
			c1[i], r1[i], err = statement.Pk.Encrypt(w1[i], p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot encrypt w1i")
			}
			w2[i], err = statement.Pk.PlainTextSub(w1[i], lowBound)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot compute w2i")
			}
			c2[i], r2[i], err = statement.Pk.Encrypt(w2[i], p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot encrypt w2i")
			}
		case 1:
			wj[i], err = randomInRange(lowBound, highBound, p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot compute w1i")
			}
			cji, rji, err := statement.Pk.Encrypt(wj[i], p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot encrypt wji")
			}
			wZero := new(saferith.Int)
			cZero, _, err := statement.Pk.Encrypt(wZero, p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot encrypt zero")
			}

			var ji [1]byte
			_, err = io.ReadFull(p.prng, ji[:])
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot sample j")
			}
			j[i] = uint(1 + (ji[0] % 2))
			switch j[i] {
			case 1:
				c1[i], err = statement.Pk.CipherTextSub(cji, statement.C)
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "cannot compute c1")
				}
				c2[i] = cZero
				rj[i] = rji
			case 2:
				c2[i], err = statement.Pk.CipherTextSub(cji, statement.C)
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "cannot compute c2")
				}
				c1[i] = cZero
				rj[i] = rji
			default:
				panic("this should never happen")
			}
		default:
			panic("this should never happen")
		}
	}

	a := &Commitment{
		C1: c1,
		C2: c2,
	}
	z := &Response{
		W1: w1,
		R1: r1,
		W2: w2,
		R2: r2,
		Wj: wj,
		Rj: rj,
		J:  j,
	}
	return a, z, nil
}

func (*PaillierRange) SpecialSoundness() uint {
	return 2
}

func (*PaillierRange) ValidateStatement(statement *Statement, witness *Witness) error {
	if !statement.Pk.Equal(&witness.Sk.PublicKey) {
		return errs.NewValidation("paillier keys mismatch")
	}
	cCheck, err := witness.Sk.EncryptWithNonce(witness.X, witness.R)
	if err != nil || !statement.Pk.CipherTextEqual(statement.C, cCheck) {
		return errs.NewValidation("plaintext/ciphertext mismatch")
	}

	lowBound, err := statement.Pk.PlainTextNeg(new(saferith.Int).SetNat(statement.L))
	if err != nil {
		return errs.NewValidation("cannot compute low bound")
	}
	highBound, err := statement.Pk.PlainTextAdd(new(saferith.Int).SetNat(statement.L), new(saferith.Int).SetNat(statement.L))
	if err != nil {
		return errs.NewValidation("cannot compute high bound")
	}

	if !isInRange(lowBound, highBound, witness.X) {
		return errs.NewValidation("witness out of range")
	}

	return nil
}

func (p *PaillierRange) GetChallengeBytesLength() int {
	return int((p.t + 7) / 8)
}

func (*PaillierRange) SerializeStatement(statement *Statement) []byte {
	return slices.Concat(
		statement.Pk.N.Big().Bytes(), []byte(":"),
		statement.C.C.Big().Bytes(), []byte(":"),
		statement.L.Big().Bytes(),
	)
}

func (p *PaillierRange) SerializeCommitment(commitment *Commitment) []byte {
	var a []byte
	for i := range p.t {
		a = append(a, commitment.C1[i].C.Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, commitment.C2[i].C.Big().Bytes()...)
		a = append(a, []byte("|")...)
	}

	return a
}

func (p *PaillierRange) SerializeResponse(response *Response) []byte {
	var a []byte

	for i := range p.t {
		a = append(a, response.W1[i].Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.R1[i].Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.W2[i].Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.R2[i].Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.Wj[i].Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.Rj[i].Big().Bytes()...)
		a = append(a, []byte("|")...)
	}

	return a
}

func (p *PaillierRange) SoundnessError() int {
	return int(p.t)
}

func randomInRange(lowInclusive, highExclusive *paillier.PlainText, prng io.Reader) (*paillier.PlainText, error) {
	boundRange := new(saferith.Int).Add(highExclusive, lowInclusive.Clone().Neg(1), highExclusive.AnnouncedLen())
	v, err := crand.Int(prng, boundRange.Big())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample random")
	}
	v.Add(v, lowInclusive.Big())

	return new(saferith.Int).SetBig(v, highExclusive.AnnouncedLen()), nil
}

// func isLess(highExclusive, v *paillier.PlainText) bool {
//	_, _, l := v.Cmp(highExclusive)
//	return l != 0
// }.

func isLess(lhs, rhs *saferith.Int) bool {
	// this is ridiculous that Int doesn't have any methods to compare
	gtAbs, _, ltAbs := lhs.Abs().Cmp(rhs.Abs())
	lNeg := lhs.IsNegative() != 0
	rNeg := rhs.IsNegative() != 0

	switch {
	case lNeg && rNeg:
		return gtAbs != 0
	case !lNeg && !rNeg:
		return ltAbs != 0
	case lNeg:
		return true
	default:
		return false
	}
}

func isInRange(lowInclusive, highExclusive, v *paillier.PlainText) bool {
	return !isLess(v, lowInclusive) && isLess(v, highExclusive)
}
