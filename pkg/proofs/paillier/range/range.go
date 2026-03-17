package paillierrange

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Name identifies the Paillier range proof protocol.
const Name = "PaillierRange"

var (
	_ sigma.Witness                                                        = (*Witness)(nil)
	_ sigma.Statement                                                      = (*Statement)(nil)
	_ sigma.Commitment                                                     = (*Commitment)(nil)
	_ sigma.State                                                          = (*State)(nil)
	_ sigma.Response                                                       = (*Response)(nil)
	_ sigma.Protocol[*Statement, *Witness, *Commitment, *State, *Response] = (*Protocol)(nil)
)

// Witness contains the secret inputs for the range proof.
type Witness struct {
	Sk *paillier.PrivateKey
	X  *paillier.Plaintext
	R  *paillier.Nonce
}

// Bytes serialises the witness for transcript binding.
func (w *Witness) Bytes() []byte {
	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, w.Sk.Group().Modulus().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, w.X.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, w.R.Value().Bytes())
	return out
}

// NewWitness constructs a range-proof witness.
func NewWitness(sk *paillier.PrivateKey, x *paillier.Plaintext, r *paillier.Nonce) *Witness {
	return &Witness{
		Sk: sk,
		X:  x,
		R:  r,
	}
}

// Statement defines the public inputs for the range proof.
type Statement struct {
	Pk *paillier.PublicKey
	C  *paillier.Ciphertext
	L  *numct.Nat
}

// Bytes serialises the statement for transcript binding.
func (x *Statement) Bytes() []byte {
	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, x.Pk.Group().Modulus().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, x.C.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, x.L.Bytes())
	return out
}

// NewStatement constructs a range-proof statement.
func NewStatement(pk *paillier.PublicKey, c *paillier.Ciphertext, l *numct.Nat) *Statement {
	return &Statement{
		Pk: pk,
		C:  c,
		L:  l,
	}
}

// Commitment holds the prover commitment for the range proof.
type Commitment struct {
	C1 []*paillier.Ciphertext
	C2 []*paillier.Ciphertext
}

// Bytes serialises the commitment for transcript binding.
func (a *Commitment) Bytes() []byte {
	c1Bytes := sliceutils.Map(a.C1, func(in *paillier.Ciphertext) []byte {
		if in == nil || in.Value() == nil {
			return nil
		}
		return in.Value().Bytes()
	})
	c2Bytes := sliceutils.Map(a.C2, func(in *paillier.Ciphertext) []byte {
		if in == nil || in.Value() == nil {
			return nil
		}
		return in.Value().Bytes()
	})

	out := []byte{}
	out = sliceutils.AppendLengthPrefixedSlices(out, c1Bytes...)
	out = sliceutils.AppendLengthPrefixedSlices(out, c2Bytes...)
	return out
}

// State stores the prover's internal state between rounds.
type State struct {
	W1 []*paillier.Plaintext
	R1 []*paillier.Nonce
	W2 []*paillier.Plaintext
	R2 []*paillier.Nonce
}

// Response is the prover response for the range proof.
type Response struct {
	W1 []*paillier.Plaintext
	R1 []*paillier.Nonce
	W2 []*paillier.Plaintext
	R2 []*paillier.Nonce
	Wj []*paillier.Plaintext
	Rj []*paillier.Nonce
	J  []uint
}

// Bytes serialises the response for transcript binding.
func (z *Response) Bytes() []byte {
	w1Bytes := sliceutils.Map(z.W1, func(in *paillier.Plaintext) []byte {
		if in == nil || in.Value() == nil {
			return nil
		}
		return in.Value().Bytes()
	})
	r1Bytes := sliceutils.Map(z.R1, func(in *paillier.Nonce) []byte {
		if in == nil || in.Value() == nil {
			return nil
		}
		return in.Value().Bytes()
	})
	w2Bytes := sliceutils.Map(z.W2, func(in *paillier.Plaintext) []byte {
		if in == nil || in.Value() == nil {
			return nil
		}
		return in.Value().Bytes()
	})
	r2Bytes := sliceutils.Map(z.R2, func(in *paillier.Nonce) []byte {
		if in == nil || in.Value() == nil {
			return nil
		}
		return in.Value().Bytes()
	})
	wjBytes := sliceutils.Map(z.Wj, func(in *paillier.Plaintext) []byte {
		if in == nil || in.Value() == nil {
			return nil
		}
		return in.Value().Bytes()
	})
	rjBytes := sliceutils.Map(z.Rj, func(in *paillier.Nonce) []byte {
		if in == nil || in.Value() == nil {
			return nil
		}
		return in.Value().Bytes()
	})
	jBytes := sliceutils.Map(z.J, func(in uint) []byte { return binary.LittleEndian.AppendUint64(nil, uint64(in)) })

	out := []byte{}
	out = sliceutils.AppendLengthPrefixedSlices(out, w1Bytes...)
	out = sliceutils.AppendLengthPrefixedSlices(out, r1Bytes...)
	out = sliceutils.AppendLengthPrefixedSlices(out, w2Bytes...)
	out = sliceutils.AppendLengthPrefixedSlices(out, r2Bytes...)
	out = sliceutils.AppendLengthPrefixedSlices(out, wjBytes...)
	out = sliceutils.AppendLengthPrefixedSlices(out, rjBytes...)
	out = sliceutils.AppendLengthPrefixedSlices(out, jBytes...)
	return out
}

// Protocol implements the Paillier range proof.
type Protocol struct {
	t    uint
	prng io.Reader
}

// NewPaillierRange constructs a Paillier range-proof protocol instance.
func NewPaillierRange(t uint, prng io.Reader) (*Protocol, error) {
	if t < base.StatisticalSecurityBits {
		return nil, ErrValidationFailed.WithMessage("insufficient statistical security")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("nil prng")
	}

	return &Protocol{
		t:    t,
		prng: prng,
	}, nil
}

// Name returns the protocol identifier.
func (*Protocol) Name() sigma.Name {
	return Name
}

// ComputeProverCommitment generates the initial commitment and state.
func (p *Protocol) ComputeProverCommitment(statement *Statement, witness *Witness) (*Commitment, *State, error) {
	ps := statement.Pk.PlaintextSpace()
	lowBound, err := ps.FromNat(statement.L)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create new plaintext")
	}
	highBound := lowBound.Add(lowBound)
	swaps := make([]byte, (p.t+7)/8)
	_, err = io.ReadFull(p.prng, swaps)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot generate randomness")
	}

	w := make([]*paillier.Plaintext, 2*p.t)
	for i := range p.t {
		w1i, err := ps.Sample(lowBound, highBound, p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot compute w1i")
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
		return nil, nil, errs.Wrap(err).WithMessage("cannot create self encrypter")
	}
	c, r, err := senc.SelfEncryptMany(w, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt state")
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

// ComputeProverResponse generates the response for a given challenge.
func (p *Protocol) ComputeProverResponse(statement *Statement, witness *Witness, _ *Commitment, state *State, challenge sigma.ChallengeBytes) (*Response, error) {
	if len(state.W1) != int(p.t) || len(state.R1) != int(p.t) || len(state.W2) != int(p.t) || len(state.R2) != int(p.t) {
		return nil, ErrInvalidArgument.WithMessage("inconsistent input")
	}

	ps := statement.Pk.PlaintextSpace()
	lowBound, err := ps.FromNat(statement.L)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create new plaintext")
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

// Verify checks a prover response against the statement and commitment.
func (p *Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	if len(commitment.C1) != int(p.t) || len(commitment.C2) != int(p.t) {
		return ErrFailed.WithMessage("inconsistent input")
	}
	if len(response.W1) != int(p.t) || len(response.R1) != int(p.t) || len(response.W2) != int(p.t) || len(response.R2) != int(p.t) || len(response.Wj) != int(p.t) || len(response.Rj) != int(p.t) || len(response.J) != int(p.t) {
		return ErrFailed.WithMessage("inconsistent input")
	}

	ps := statement.Pk.PlaintextSpace()
	lowBound, err := ps.FromNat(statement.L)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create new plaintext")
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
			if (!isInRange(lowBound, highBound, w1i) || !isInRange(ps.Zero(), lowBound, w2i)) &&
				(!isInRange(lowBound, highBound, w2i) || !isInRange(ps.Zero(), lowBound, w1i)) {

				return ErrVerificationFailed.WithMessage("verification failed")
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
				return ErrVerificationFailed.WithMessage("verification failed")
			}

			w = append(w, wi)
			r = append(r, response.Rj[i])

			switch response.J[i] {
			case 1:
				ci := statement.C.HomAdd(commitment.C1[i])
				c = append(c, ci)
			case 2:
				ci := statement.C.HomAdd(commitment.C2[i])
				c = append(c, ci)
			default:
				return ErrVerificationFailed.WithMessage("verification failed")
			}
		default:
			panic("this should never happen")
		}
	}

	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create encrypter")
	}
	cCheck, err := enc.EncryptManyWithNonces(w, statement.Pk, r)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot compute encrypted ciphertext")
	}
	for i, ci := range c {
		if !cCheck[i].Equal(ci) {
			return ErrVerificationFailed.WithMessage("verification failed")
		}
	}

	return nil
}

// RunSimulator creates a simulated transcript for a given challenge.
func (p *Protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	ps := statement.Pk.PlaintextSpace()
	lowBound, err := ps.FromNat(statement.L)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create new plaintext")
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
		return nil, nil, errs.Wrap(err).WithMessage("cannot create encrypter")
	}

	toBeEncrypted := make([]*paillier.Plaintext, p.t*2)
	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			w1[i], err = ps.Sample(lowBound, highBound, p.prng)
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot compute w1i")
			}
			w2[i] = w1[i].Sub(lowBound)
			toBeEncrypted[i] = w1[i]
			toBeEncrypted[i+p.t] = w2[i]
		case 1:
			wj[i], err = ps.Sample(lowBound, highBound, p.prng)
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot compute w1i")
			}
			toBeEncrypted[i] = wj[i]
			toBeEncrypted[i+p.t] = ps.Zero()
		default:
			panic("this should never happen")
		}
	}

	ctxs, rs, err := enc.EncryptMany(toBeEncrypted, statement.Pk, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt many")
	}

	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			// Extract encrypted values for w1 and w2
			c1[i] = ctxs[i]
			r1[i] = rs[i]
			c2[i] = ctxs[i+p.t]
			r2[i] = rs[i+p.t]
		case 1:
			cji := ctxs[i]
			rji := rs[i]
			cZero := ctxs[i+p.t]
			var ji [1]byte
			_, err = io.ReadFull(p.prng, ji[:])
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot sample j")
			}
			j[i] = uint(1 + (ji[0] % 2))
			switch j[i] {
			case 1:
				c1[i] = cji.HomSub(statement.C)
				c2[i] = cZero
				rj[i] = rji
			case 2:
				c2[i] = cji.HomSub(statement.C)
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

// SpecialSoundness returns the protocol special soundness parameter.
func (*Protocol) SpecialSoundness() uint {
	return 2
}

// ValidateStatement checks the witness against the statement.
func (*Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if !statement.Pk.Equal(witness.Sk.PublicKey()) {
		return ErrValidationFailed.WithMessage("paillier keys mismatch")
	}
	senc, err := paillier.NewScheme().SelfEncrypter(witness.Sk)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create self encrypter")
	}
	cCheck, err := senc.SelfEncryptWithNonce(witness.X, witness.R)
	if err != nil || !statement.C.Equal(cCheck) {
		return ErrValidationFailed.WithMessage("plaintext/ciphertext mismatch")
	}

	var negL, twoL, L numct.Int
	L.SetNat(statement.L)
	negL.Neg(&L)
	twoL.Double(&L)

	lowBound, err := statement.Pk.PlaintextSpace().FromInt(&negL)
	if err != nil {
		return ErrValidationFailed.WithMessage("cannot compute low bound")
	}
	highBound, err := statement.Pk.PlaintextSpace().FromInt(&twoL)
	if err != nil {
		return ErrValidationFailed.WithMessage("cannot compute high bound")
	}

	if !isInRange(lowBound, highBound, witness.X) {
		return ErrValidationFailed.WithMessage("witness out of range")
	}

	return nil
}

// GetChallengeBytesLength returns the challenge size in bytes.
func (p *Protocol) GetChallengeBytesLength() int {
	return int((p.t + 7) / 8)
}

// SoundnessError returns the protocol soundness error.
func (p *Protocol) SoundnessError() uint {
	return p.t
}

func isInRange(lowInclusive, highExclusive, v *paillier.Plaintext) bool {
	return lowInclusive.IsLessThanOrEqual(v) && v.IsLessThanOrEqual(highExclusive) && !highExclusive.Equal(v)
}
