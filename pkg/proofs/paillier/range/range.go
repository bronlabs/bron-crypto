package paillierrange

import (
	"bytes"
	"encoding/binary"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name = "PaillierRange"

var (
	_ sigma.Witness                                                        = (*Witness)(nil)
	_ sigma.Statement                                                      = (*Statement)(nil)
	_ sigma.Commitment                                                     = (*Commitment)(nil)
	_ sigma.Statement                                                      = (*State)(nil)
	_ sigma.Response                                                       = (*Response)(nil)
	_ sigma.Protocol[*Statement, *Witness, *Commitment, *State, *Response] = (*Protocol)(nil)
)

type Witness struct {
	Sk *paillier.PrivateKey
	X  *paillier.Plaintext
	R  *paillier.Nonce
}

func (w *Witness) Bytes() []byte {
	var buf bytes.Buffer
	buf.Write(w.Sk.Group().Modulus().Bytes())
	buf.Write(w.X.Value().Bytes())
	buf.Write(w.R.Value().Bytes())
	return buf.Bytes()
}

func NewWitness(sk *paillier.PrivateKey, x *paillier.Plaintext, r *paillier.Nonce) *Witness {
	return &Witness{
		Sk: sk,
		X:  x,
		R:  r,
	}
}

type Statement struct {
	Pk *paillier.PublicKey
	C  *paillier.Ciphertext
	L  *numct.Nat
}

func (s *Statement) Bytes() []byte {
	var buf bytes.Buffer
	buf.Write(s.Pk.Group().Modulus().Bytes())
	buf.Write(s.C.Value().Bytes())
	buf.Write(s.L.Bytes())
	return buf.Bytes()
}

func NewStatement(pk *paillier.PublicKey, c *paillier.Ciphertext, l *numct.Nat) *Statement {
	return &Statement{
		Pk: pk,
		C:  c,
		L:  l,
	}
}

type Commitment struct {
	C1 []*paillier.Ciphertext
	C2 []*paillier.Ciphertext
}

func (c *Commitment) Bytes() []byte {
	var buf bytes.Buffer
	for _, ci := range c.C1 {
		buf.Write(ci.Value().Bytes())
	}
	for _, ci := range c.C2 {
		buf.Write(ci.Value().Bytes())
	}
	return buf.Bytes()
}

type State struct {
	W1 []*paillier.Plaintext
	R1 []*paillier.Nonce
	W2 []*paillier.Plaintext
	R2 []*paillier.Nonce
}

func (s *State) Bytes() []byte {
	var buf bytes.Buffer
	for _, wi := range s.W1 {
		buf.Write(wi.Value().Bytes())
	}
	for _, ri := range s.R1 {
		buf.Write(ri.Value().Bytes())
	}
	for _, wi := range s.W2 {
		buf.Write(wi.Value().Bytes())
	}
	for _, ri := range s.R2 {
		buf.Write(ri.Value().Bytes())
	}
	return buf.Bytes()
}

type Response struct {
	W1 []*paillier.Plaintext
	R1 []*paillier.Nonce
	W2 []*paillier.Plaintext
	R2 []*paillier.Nonce
	Wj []*paillier.Plaintext
	Rj []*paillier.Nonce
	J  []uint
}

func (r *Response) Bytes() []byte {
	var buf bytes.Buffer
	for _, wi := range r.W1 {
		buf.Write(wi.Value().Bytes())
	}
	for _, ri := range r.R1 {
		buf.Write(ri.Value().Bytes())
	}
	for _, wi := range r.W2 {
		buf.Write(wi.Value().Bytes())
	}
	for _, ri := range r.R2 {
		buf.Write(ri.Value().Bytes())
	}
	for _, wi := range r.Wj {
		buf.Write(wi.Value().Bytes())
	}
	for _, ri := range r.Rj {
		buf.Write(ri.Value().Bytes())
	}
	for _, ji := range r.J {
		jib := make([]byte, 8)
		binary.BigEndian.PutUint64(jib, uint64(ji))
		buf.Write(jib)
	}
	return buf.Bytes()
}

type Protocol struct {
	t    uint
	prng io.Reader
}

func NewPaillierRange(t uint, prng io.Reader) (*Protocol, error) {
	if t < base.StatisticalSecurityBits {
		return nil, errs.NewValidation("insufficient statistical security")
	}
	if prng == nil {
		return nil, errs.NewIsNil("nil prng")
	}

	return &Protocol{
		t:    t,
		prng: prng,
	}, nil
}

func (*Protocol) Name() sigma.Name {
	return Name
}

func (p *Protocol) ComputeProverCommitment(statement *Statement, witness *Witness) (*Commitment, *State, error) {
	ps := statement.Pk.PlaintextSpace()
	lowBound, err := ps.New(statement.L)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create new plaintext")
	}
	highBound := lowBound.Add(lowBound)
	swaps := make([]byte, (p.t+7)/8)
	_, err = io.ReadFull(p.prng, swaps)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot generate randomness")
	}

	w := make([]*paillier.Plaintext, 2*p.t)
	for i := range p.t {
		w1i, err := ps.Sample(lowBound, highBound, p.prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot compute w1i")
		}
		w2i := w1i.Sub(lowBound)
		swapBit := (swaps[i/8] >> (i % 8)) % 2
		if swapBit != 0 {
			w1i, w2i = w2i, w1i
		}

		w[i] = w1i
		w[p.t+i] = w2i
	}
	senc, err := paillier.NewScheme().SelfEncrypter(witness.Sk)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create self encrypter")
	}
	c, r, err := senc.SelfEncryptMany(w, p.prng)
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

func (p *Protocol) ComputeProverResponse(statement *Statement, witness *Witness, _ *Commitment, state *State, challenge sigma.ChallengeBytes) (*Response, error) {
	ps := statement.Pk.PlaintextSpace()
	lowBound, err := ps.New(statement.L)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create new plaintext")
	}
	highBound := lowBound.Add(lowBound)

	z := &Response{
		W1: make([]*paillier.Plaintext, p.t),
		R1: make([]*paillier.Nonce, p.t),
		W2: make([]*paillier.Plaintext, p.t),
		R2: make([]*paillier.Nonce, p.t),
		Wj: make([]*paillier.Plaintext, p.t),
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
			z.Wj[i] = new(paillier.Plaintext)
			z.Rj[i] = new(paillier.Nonce)
			z.J[i] = 0
		case 1:
			xPlusW1 := witness.X.Add(state.W1[i])
			if isInRange(lowBound, highBound, xPlusW1) {
				z.Wj[i] = xPlusW1
				z.Rj[i] = witness.R.Mul(state.R1[i])
				z.J[i] = 1
			} else {
				xPlusW2 := witness.X.Add(state.W2[i])
				z.Wj[i] = xPlusW2
				z.Rj[i] = witness.R.Mul(state.R2[i])
				z.J[i] = 2
			}

			// put some dummy value to it can be serialised
			z.W1[i] = new(paillier.Plaintext)
			z.R1[i] = new(paillier.Nonce)
			z.W2[i] = new(paillier.Plaintext)
			z.R2[i] = new(paillier.Nonce)
		default:
			panic("this should never happen")
		}
	}

	return z, nil
}

func (p *Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	ps := statement.Pk.PlaintextSpace()
	lowBound, err := ps.New(statement.L)
	if err != nil {
		return errs.WrapFailed(err, "cannot create new plaintext")
	}
	highBound := lowBound.Add(lowBound)

	var c []*paillier.Ciphertext
	var w []*paillier.Plaintext
	var r []*paillier.Nonce
	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			w1i := response.W1[i]
			w2i := response.W2[i]
			if !((isInRange(lowBound, highBound, w1i) && isInRange(ps.Zero(), lowBound, w2i)) ||
				isInRange(lowBound, highBound, w2i) && isInRange(ps.Zero(), lowBound, w1i)) {

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
				ci := statement.C.Mul(commitment.C1[i])
				c = append(c, ci)
			case 2:
				ci := statement.C.Mul(commitment.C2[i])
				c = append(c, ci)
			default:
				return errs.NewVerification("verification failed")
			}
		default:
			panic("this should never happen")
		}
	}

	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return errs.WrapFailed(err, "cannot create encrypter")
	}
	cCheck, err := enc.EncryptManyWithNonces(w, statement.Pk, r)
	if err != nil {
		return errs.WrapFailed(err, "cannot compute encrypted ciphertext")
	}
	for i, ci := range c {
		if !cCheck[i].Equal(ci) {
			return errs.NewVerification("verification failed")
		}
	}

	return nil
}

func (p *Protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	ps := statement.Pk.PlaintextSpace()
	lowBound, err := ps.New(statement.L)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create new plaintext")
	}
	highBound := lowBound.Add(lowBound)

	w1 := make([]*paillier.Plaintext, p.t)
	r1 := make([]*paillier.Nonce, p.t)
	c1 := make([]*paillier.Ciphertext, p.t)
	w2 := make([]*paillier.Plaintext, p.t)
	r2 := make([]*paillier.Nonce, p.t)
	c2 := make([]*paillier.Ciphertext, p.t)
	wj := make([]*paillier.Plaintext, p.t)
	rj := make([]*paillier.Nonce, p.t)
	j := make([]uint, p.t)

	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create encrypter")
	}

	// TODO(mkk): refactor to use EncryptMany
	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			w1[i], err = ps.Sample(lowBound, highBound, p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot compute w1i")
			}
			c1[i], r1[i], err = enc.Encrypt(w1[i], statement.Pk, p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot encrypt w1i")
			}
			w2[i] = w1[i].Sub(lowBound)
			c2[i], r2[i], err = enc.Encrypt(w2[i], statement.Pk, p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot encrypt w2i")
			}
		case 1:
			wj[i], err = ps.Sample(lowBound, highBound, p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot compute w1i")
			}
			cji, rji, err := enc.Encrypt(wj[i], statement.Pk, p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot encrypt wji")
			}
			cZero, _, err := enc.Encrypt(ps.Zero(), statement.Pk, p.prng)
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
				c1[i] = cji.Div(statement.C)
				c2[i] = cZero
				rj[i] = rji
			case 2:
				c2[i] = cji.Div(statement.C)
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

func (*Protocol) SpecialSoundness() uint {
	return 2
}

func (*Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if !statement.Pk.Equal(witness.Sk.PublicKey()) {
		return errs.NewValidation("paillier keys mismatch")
	}
	senc, err := paillier.NewScheme().SelfEncrypter(witness.Sk)
	if err != nil {
		return errs.WrapFailed(err, "failed to create self encrypter")
	}
	cCheck, err := senc.SelfEncryptWithNonce(witness.X, witness.R)
	if err != nil || !statement.C.Equal(cCheck) {
		return errs.NewValidation("plaintext/ciphertext mismatch")
	}

	// var negL, intL *numct.Int
	// intL.SetNat(statement.L)
	// negL.Neg(intL)

	// lowBound, err := statement.Pk.PlainTextNeg(new(saferith.Int).SetNat(statement.L))
	// if err != nil {
	// 	return errs.NewValidation("cannot compute low bound")
	// }
	// highBound, err := statement.Pk.PlainTextAdd(new(saferith.Int).SetNat(statement.L), new(saferith.Int).SetNat(statement.L))
	// if err != nil {
	// 	return errs.NewValidation("cannot compute high bound")
	// }

	// if !isInRange(lowBound, highBound, witness.X) {
	// 	return errs.NewValidation("witness out of range")
	// }

	return nil
}

func (p *Protocol) GetChallengeBytesLength() int {
	return int((p.t + 7) / 8)
}

func (*Protocol) SerializeStatement(statement *Statement) []byte {
	return slices.Concat(
		statement.Pk.N().Big().Bytes(), []byte(":"),
		statement.C.ValueCT().Big().Bytes(), []byte(":"),
		statement.L.Big().Bytes(),
	)
}

func (p *Protocol) SerializeCommitment(commitment *Commitment) []byte {
	var a []byte
	for i := range p.t {
		a = append(a, commitment.C1[i].ValueCT().Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, commitment.C2[i].ValueCT().Big().Bytes()...)
		a = append(a, []byte("|")...)
	}

	return a
}

func (p *Protocol) SerializeResponse(response *Response) []byte {
	var a []byte

	for i := range p.t {
		a = append(a, response.W1[i].ValueCT().Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.R1[i].ValueCT().Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.W2[i].ValueCT().Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.R2[i].ValueCT().Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.Wj[i].ValueCT().Big().Bytes()...)
		a = append(a, []byte(":")...)
		a = append(a, response.Rj[i].ValueCT().Big().Bytes()...)
		a = append(a, []byte("|")...)
	}

	return a
}

func (p *Protocol) SoundnessError() uint {
	return p.t
}

// func isLess(highExclusive, v *paillier.PlainText) bool {
//	_, _, l := v.Cmp(highExclusive)
//	return l != 0
// }.

// func isLess(lhs, rhs *saferith.Int) bool {
// 	// this is ridiculous that Int doesn't have any methods to compare
// 	gtAbs, _, ltAbs := lhs.Abs().Cmp(rhs.Abs())
// 	lNeg := lhs.IsNegative() != 0
// 	rNeg := rhs.IsNegative() != 0

// 	switch {
// 	case lNeg && rNeg:
// 		return gtAbs != 0
// 	case !lNeg && !rNeg:
// 		return ltAbs != 0
// 	case lNeg:
// 		return true
// 	default:
// 		return false
// 	}
// }

func isInRange(lowInclusive, highExclusive, v *paillier.Plaintext) bool {
	return lowInclusive.IsLessThanOrEqual(v) && v.IsLessThanOrEqual(highExclusive) && !highExclusive.Equal(v)
}
