package paillierrange

import (
	"encoding/binary"
	"io"
	"maps"
	"slices"

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
	X *paillier.Plaintext
	R *paillier.Nonce
}

// Bytes serialises the witness for transcript binding.
func (w *Witness) Bytes() []byte {
	if w == nil {
		return nil
	}

	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, w.X.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, w.R.Value().Bytes())
	return out
}

// NewWitness constructs a range-proof witness.
func NewWitness(x *paillier.Plaintext, r *paillier.Nonce) *Witness {
	return &Witness{
		X: x,
		R: r,
	}
}

// Statement defines the public inputs for the range proof.
type Statement struct {
	C *paillier.Ciphertext
}

// Bytes serialises the statement for transcript binding.
func (s *Statement) Bytes() []byte {
	if s == nil {
		return nil
	}

	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, s.C.Value().Bytes())
	return out
}

// NewStatement constructs a range-proof statement.
func NewStatement(pk *paillier.PublicKey, c *paillier.Ciphertext) *Statement {
	return &Statement{
		C: c,
	}
}

// Commitment holds the prover commitment for the range proof.
type Commitment struct {
	C1 []*paillier.Ciphertext
	C2 []*paillier.Ciphertext
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment) Bytes() []byte {
	if c == nil {
		return nil
	}

	c1Bytes := sliceutils.Map(c.C1, func(c1 *paillier.Ciphertext) []byte { return c1.Bytes() })
	c2Bytes := sliceutils.Map(c.C2, func(c2 *paillier.Ciphertext) []byte { return c2.Bytes() })

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
	W1 map[uint]*paillier.Plaintext
	R1 map[uint]*paillier.Nonce
	W2 map[uint]*paillier.Plaintext
	R2 map[uint]*paillier.Nonce
	Wj map[uint]*paillier.Plaintext
	Rj map[uint]*paillier.Nonce
	J  map[uint]uint
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	if r == nil {
		return nil
	}

	out := []byte{}
	out = binary.LittleEndian.AppendUint64(out, uint64(len(r.W1)))
	for _, k := range slices.Sorted(maps.Keys(r.W1)) {
		out = binary.LittleEndian.AppendUint64(out, uint64(k))
		out = sliceutils.AppendLengthPrefixed(out, r.W1[k].Bytes())
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(len(r.R1)))
	for _, k := range slices.Sorted(maps.Keys(r.R1)) {
		out = binary.LittleEndian.AppendUint64(out, uint64(k))
		out = sliceutils.AppendLengthPrefixed(out, r.R1[k].Bytes())
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(len(r.W2)))
	for _, k := range slices.Sorted(maps.Keys(r.W2)) {
		out = binary.LittleEndian.AppendUint64(out, uint64(k))
		out = sliceutils.AppendLengthPrefixed(out, r.W2[k].Bytes())
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(len(r.R2)))
	for _, k := range slices.Sorted(maps.Keys(r.R2)) {
		out = binary.LittleEndian.AppendUint64(out, uint64(k))
		out = sliceutils.AppendLengthPrefixed(out, r.R2[k].Bytes())
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(len(r.Wj)))
	for _, k := range slices.Sorted(maps.Keys(r.Wj)) {
		out = binary.LittleEndian.AppendUint64(out, uint64(k))
		out = sliceutils.AppendLengthPrefixed(out, r.Wj[k].Bytes())
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(len(r.Rj)))
	for _, k := range slices.Sorted(maps.Keys(r.Rj)) {
		out = binary.LittleEndian.AppendUint64(out, uint64(k))
		out = sliceutils.AppendLengthPrefixed(out, r.Rj[k].Bytes())
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(len(r.J)))
	for _, k := range slices.Sorted(maps.Keys(r.J)) {
		out = binary.LittleEndian.AppendUint64(out, uint64(k))
		out = binary.LittleEndian.AppendUint64(out, uint64(r.J[k]))
	}

	return out
}

// Protocol implements the Paillier range proof.
type Protocol struct {
	t         uint
	lowBound  *paillier.Plaintext
	highBound *paillier.Plaintext
	sk        *paillier.PrivateKey
	pk        *paillier.PublicKey
}

// NewPaillierRange constructs a Paillier range-proof protocol instance.
func NewPaillierRange(t uint, l *numct.Nat, sk *paillier.PrivateKey, pk *paillier.PublicKey) (*Protocol, error) {
	if t < base.StatisticalSecurityBits {
		return nil, ErrValidationFailed.WithMessage("insufficient statistical security")
	}
	if l == nil {
		return nil, ErrInvalidArgument.WithMessage("nil l")
	}
	if sk == nil && pk == nil {
		return nil, ErrInvalidArgument.WithMessage("at least one of sk or pk must be provided")
	}
	if sk != nil {
		if pk != nil && !sk.PublicKey().Equal(pk) {
			return nil, ErrInvalidArgument.WithMessage("paillier keys mismatch")
		}
		pk = sk.PublicKey()
	}

	ps := pk.PlaintextSpace()
	lowBound, err := ps.FromNat(l)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create new plaintext")
	}
	highBound := lowBound.Add(lowBound)

	return &Protocol{
		t:         t,
		lowBound:  lowBound,
		highBound: highBound,
		sk:        sk,
		pk:        pk,
	}, nil
}

// Name returns the protocol identifier.
func (*Protocol) Name() sigma.Name {
	return Name
}

func (p *Protocol) SampleProverState(_ *Witness, prng io.Reader) (*State, error) {
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("nil prng")
	}

	ps := p.pk.PlaintextSpace()

	swaps := make([]byte, (p.t+7)/8)
	if _, err := io.ReadFull(prng, swaps); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate randomness")
	}

	w := make([]*paillier.Plaintext, 2*p.t)
	for i := range p.t {
		w1i, err := ps.Sample(p.lowBound, p.highBound, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot compute w1i")
		}
		w2i := w1i.Sub(p.lowBound)
		swapBit := (swaps[i/8] >> (i % 8)) % 2
		if swapBit != 0 {
			w1i, w2i = w2i, w1i
		}

		w[i] = w1i
		w[p.t+i] = w2i
	}

	ns := p.pk.NonceSpace()
	r := make([]*paillier.Nonce, len(w))
	for i := range w {
		ri, err := ns.Sample(prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample nonce")
		}
		r[i] = ri
	}
	return &State{
		W1: w[:p.t],
		R1: r[:p.t],
		W2: w[p.t:],
		R2: r[p.t:],
	}, nil
}

// ComputeProverCommitment generates the initial commitment and state.
func (p *Protocol) ComputeProverCommitment(state *State) (*Commitment, error) {
	if p.sk == nil {
		return nil, ErrInvalidArgument.WithMessage("protocol instance cannot compute commitment without secret key")
	}
	if state == nil {
		return nil, ErrInvalidArgument.WithMessage("nil state")
	}

	w := slices.Concat(state.W1, state.W2)
	r := slices.Concat(state.R1, state.R2)
	senc, err := paillier.NewScheme().SelfEncrypter(p.sk)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create self encrypter")
	}
	c, err := senc.SelfEncryptManyWithNonces(w, r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt state")
	}
	return &Commitment{
		C1: c[:p.t],
		C2: c[p.t:],
	}, nil
}

// ComputeProverResponse generates the response for a given challenge.
func (p *Protocol) ComputeProverResponse(witness *Witness, state *State, challenge sigma.ChallengeBytes) (*Response, error) {
	if witness == nil || state == nil {
		return nil, ErrInvalidArgument.WithMessage("nil argument")
	}
	if len(state.W1) != int(p.t) || len(state.R1) != int(p.t) || len(state.W2) != int(p.t) || len(state.R2) != int(p.t) {
		return nil, ErrInvalidArgument.WithMessage("inconsistent input")
	}

	z := &Response{
		W1: make(map[uint]*paillier.Plaintext),
		R1: make(map[uint]*paillier.Nonce),
		W2: make(map[uint]*paillier.Plaintext),
		R2: make(map[uint]*paillier.Nonce),
		Wj: make(map[uint]*paillier.Plaintext),
		Rj: make(map[uint]*paillier.Nonce),
		J:  make(map[uint]uint),
	}

	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			z.W1[i] = state.W1[i]
			z.R1[i] = state.R1[i]
			z.W2[i] = state.W2[i]
			z.R2[i] = state.R2[i]

		case 1:
			xPlusW1 := witness.X.Add(state.W1[i])
			if isInRange(p.lowBound, p.highBound, xPlusW1) {
				z.Wj[i] = xPlusW1
				z.Rj[i] = witness.R.Mul(state.R1[i])
				z.J[i] = 1
			} else {
				xPlusW2 := witness.X.Add(state.W2[i])
				z.Wj[i] = xPlusW2
				z.Rj[i] = witness.R.Mul(state.R2[i])
				z.J[i] = 2
			}

		default:
			return nil, ErrFailed.WithMessage("unexpected challenge bit value")
		}
	}

	return z, nil
}

// Verify checks a prover response against the statement and commitment.
func (p *Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	if statement == nil || commitment == nil || response == nil {
		return ErrInvalidArgument.WithMessage("nil argument")
	}
	if len(commitment.C1) != int(p.t) || len(commitment.C2) != int(p.t) {
		return ErrFailed.WithMessage("inconsistent input")
	}

	l1 := len(response.W1)
	l2 := len(response.Wj)
	if len(response.W2) != l1 || len(response.W1) != l1 || len(response.R1) != l1 || len(response.R2) != l1 ||
		len(response.Rj) != l2 || len(response.J) != l2 || l1+l2 != int(p.t) {

		return ErrFailed.WithMessage("inconsistent input")
	}

	ps := p.pk.PlaintextSpace()
	var c []*paillier.Ciphertext
	var w []*paillier.Plaintext
	var r []*paillier.Nonce
	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			w1i, okw1i := response.W1[i]
			w2i, okw2i := response.W2[i]
			r1i, okr1i := response.R1[i]
			r2i, okr2i := response.R2[i]
			if !okw1i || !okw2i || !okr1i || !okr2i {
				return ErrVerificationFailed.WithMessage("verification failed")
			}

			if (!isInRange(p.lowBound, p.highBound, w1i) || !isInRange(ps.Zero(), p.lowBound, w2i)) &&
				(!isInRange(p.lowBound, p.highBound, w2i) || !isInRange(ps.Zero(), p.lowBound, w1i)) {

				return ErrVerificationFailed.WithMessage("verification failed")
			}

			w = append(w, w1i)
			r = append(r, r1i)
			c = append(c, commitment.C1[i])
			w = append(w, w2i)
			r = append(r, r2i)
			c = append(c, commitment.C2[i])

		case 1:
			wi, okwi := response.Wj[i]
			ri, okri := response.Rj[i]
			ji, okji := response.J[i]
			if !okwi || !okri || !okji {
				return ErrVerificationFailed.WithMessage("verification failed")
			}

			if !isInRange(p.lowBound, p.highBound, wi) {
				return ErrVerificationFailed.WithMessage("verification failed")
			}

			w = append(w, wi)
			r = append(r, ri)
			switch ji {
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
			return ErrFailed.WithMessage("unexpected challenge bit value")
		}
	}

	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create encrypter")
	}
	cCheck, err := enc.EncryptManyWithNonces(w, p.pk, r)
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
func (p *Protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes, prng io.Reader) (*Commitment, *Response, error) {
	if statement == nil || prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("nil argument")
	}
	ps := p.pk.PlaintextSpace()

	w1 := make(map[uint]*paillier.Plaintext)
	r1 := make(map[uint]*paillier.Nonce)
	c1 := make([]*paillier.Ciphertext, p.t)
	w2 := make(map[uint]*paillier.Plaintext)
	r2 := make(map[uint]*paillier.Nonce)
	c2 := make([]*paillier.Ciphertext, p.t)
	wj := make(map[uint]*paillier.Plaintext)
	rj := make(map[uint]*paillier.Nonce)
	j := make(map[uint]uint)

	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create encrypter")
	}

	toBeEncrypted := make([]*paillier.Plaintext, p.t*2)
	for i := range p.t {
		ei := (challenge[i/8] >> (i % 8)) % 2
		switch ei {
		case 0:
			w1[i], err = ps.Sample(p.lowBound, p.highBound, prng)
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot compute w1i")
			}
			w2[i] = w1[i].Sub(p.lowBound)
			toBeEncrypted[i] = w1[i]
			toBeEncrypted[i+p.t] = w2[i]
		case 1:
			wj[i], err = ps.Sample(p.lowBound, p.highBound, prng)
			if err != nil {
				return nil, nil, errs.Wrap(err).WithMessage("cannot compute w1i")
			}
			toBeEncrypted[i] = wj[i]
			toBeEncrypted[i+p.t] = ps.Zero()
		default:
			return nil, nil, ErrFailed.WithMessage("unexpected challenge bit value")
		}
	}

	ctxs, rs, err := enc.EncryptMany(toBeEncrypted, p.pk, prng)
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
			_, err = io.ReadFull(prng, ji[:])
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
				return nil, nil, ErrFailed.WithMessage("unexpected challenge bit value")
			}
		default:
			return nil, nil, ErrFailed.WithMessage("unexpected challenge bit value")
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
func (p *Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if statement == nil || witness == nil {
		return ErrInvalidArgument.WithMessage("nil argument")
	}
	senc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create self encrypter")
	}
	cCheck, err := senc.EncryptWithNonce(witness.X, p.pk, witness.R)
	if err != nil || !statement.C.Equal(cCheck) {
		return ErrValidationFailed.WithMessage("plaintext/ciphertext mismatch")
	}
	if !isInRange(p.lowBound, p.highBound, witness.X) {
		return ErrValidationFailed.WithMessage("witness out of range")
	}

	return nil
}

// DeriveStatement derives the statement from a given witness.
func (p *Protocol) DeriveStatement(witness *Witness) (*Statement, error) {
	if witness == nil {
		return nil, ErrInvalidArgument.WithMessage("nil witness")
	}
	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create encrypter")
	}
	c, err := enc.EncryptWithNonce(witness.X, p.pk, witness.R)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to encrypt witness")
	}
	return &Statement{C: c}, nil
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
