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
	Sk *paillier.PrivateKey
	X  *paillier.Plaintext
	R  *paillier.Nonce
}

// Bytes serialises the witness for transcript binding.
func (w *Witness) Bytes() []byte {
	if w == nil {
		return nil
	}

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
func (s *Statement) Bytes() []byte {
	if s == nil {
		return nil
	}

	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, s.Pk.Group().Modulus().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.C.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.L.Bytes())
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
	if statement == nil || statement.Pk == nil || statement.C == nil || statement.L == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("invalid statement")
	}
	if witness == nil || witness.Sk == nil || witness.X == nil || witness.R == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("invalid witness")
	}

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
	if statement == nil || statement.Pk == nil || statement.C == nil || statement.L == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid statement")
	}
	if witness == nil || witness.Sk == nil || witness.X == nil || witness.R == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid witness")
	}
	if state == nil {
		return nil, ErrInvalidArgument.WithMessage("state is nil")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
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

		default:
			return nil, ErrFailed.WithMessage("unexpected challenge bit value")
		}
	}

	return z, nil
}

// Verify checks a prover response against the statement and commitment.
func (p *Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	if statement == nil || statement.Pk == nil || statement.C == nil || statement.L == nil {
		return ErrInvalidArgument.WithMessage("invalid statement")
	}
	if commitment == nil || response == nil {
		return ErrInvalidArgument.WithMessage("invalid commitment or response")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return ErrInvalidArgument.WithMessage("invalid challenge length")
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
			w1i, okw1i := response.W1[i]
			w2i, okw2i := response.W2[i]
			r1i, okr1i := response.R1[i]
			r2i, okr2i := response.R2[i]
			if !okw1i || !okw2i || !okr1i || !okr2i {
				return ErrVerificationFailed.WithMessage("verification failed")
			}

			if (!isInRange(lowBound, highBound, w1i) || !isInRange(ps.Zero(), lowBound, w2i)) &&
				(!isInRange(lowBound, highBound, w2i) || !isInRange(ps.Zero(), lowBound, w1i)) {

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

			if !isInRange(lowBound, highBound, wi) {
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
	if statement == nil || statement.Pk == nil || statement.C == nil || statement.L == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("invalid statement")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	ps := statement.Pk.PlaintextSpace()
	lowBound, err := ps.FromNat(statement.L)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create new plaintext")
	}
	highBound := lowBound.Add(lowBound)

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
			return nil, nil, ErrFailed.WithMessage("unexpected challenge bit value")
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
func (*Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if statement == nil || statement.Pk == nil || statement.C == nil || statement.L == nil {
		return ErrInvalidArgument.WithMessage("invalid statement")
	}
	if witness == nil || witness.Sk == nil || witness.X == nil || witness.R == nil {
		return ErrInvalidArgument.WithMessage("invalid witness")
	}
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
