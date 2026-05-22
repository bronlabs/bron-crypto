package fac

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	// Name identifies the CGGMP21 small-factor proof.
	Name sigma.Name = "CGGMP21_SMALL_FACTOR"
)

// Statement is the public input for the small-factor proof.
type Statement struct {
	PublicKey *paillier.PublicKey
}

// NewStatement constructs a small-factor statement.
func NewStatement(publicKey *paillier.PublicKey) (*Statement, error) {
	statement := &Statement{
		PublicKey: publicKey,
	}
	if err := validatePublicKey(statement); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	return statement, nil
}

// Bytes serialises the statement for transcript binding.
func (s *Statement) Bytes() []byte {
	if s == nil || s.PublicKey == nil || s.PublicKey.Group() == nil {
		return nil
	}

	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, s.PublicKey.Group().N().Bytes())
	return out
}

// Witness contains the secret Paillier key for the statement public key.
type Witness struct {
	SecretKey *paillier.SecretKey
}

// NewWitness constructs a small-factor witness from a Paillier secret key.
func NewWitness(secretKey *paillier.SecretKey) (*Witness, error) {
	if secretKey == nil {
		return nil, ErrInvalidArgument.WithMessage("secret key must not be nil")
	}
	return &Witness{
		SecretKey: secretKey,
	}, nil
}

// Bytes serialises the witness.
func (w *Witness) Bytes() []byte {
	if w == nil || w.SecretKey == nil || w.SecretKey.Group() == nil {
		return nil
	}

	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, w.SecretKey.Group().N().Bytes())
	return out
}

// Commitment holds the prover's first-round values (P, Q, A, B, T).
type Commitment struct {
	P *intcom.Commitment `cbor:"p"`
	Q *intcom.Commitment `cbor:"q"`
	A *intcom.Commitment `cbor:"a"`
	B *intcom.Commitment `cbor:"b"`
	T *intcom.Commitment `cbor:"t"`
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment) Bytes() []byte {
	if c == nil {
		return nil
	}

	out := binary.LittleEndian.AppendUint64(nil, 5)
	for _, elem := range []*intcom.Commitment{c.P, c.Q, c.A, c.B, c.T} {
		var elemBytes []byte
		if elem != nil && elem.Value() != nil {
			elemBytes = elem.Value().Bytes()
		}
		out = sliceutils.AppendLengthPrefixed(out, elemBytes)
	}
	return out
}

func (c *Commitment) Equal(rhs *Commitment) bool {
	if c == nil || rhs == nil {
		return c == rhs
	}

	left := []*intcom.Commitment{c.P, c.Q, c.A, c.B, c.T}
	right := []*intcom.Commitment{rhs.P, rhs.Q, rhs.A, rhs.B, rhs.T}
	for i := range left {
		if left[i] == nil || right[i] == nil {
			if left[i] != right[i] {
				return false
			}
			continue
		}
		if left[i].Value() == nil || right[i].Value() == nil {
			if left[i].Value() != right[i].Value() {
				return false
			}
			continue
		}
		if !left[i].Equal(right[i]) {
			return false
		}
	}
	return true
}

// State stores the prover's internal randomness between rounds.
type State struct {
	Alpha *num.Int
	Beta  *num.Int
	Mu    *num.Int
	Nu    *num.Int
	R     *num.Int
	X     *num.Int
	Y     *num.Int
}

// Response holds the prover response (z1, z2, w1, w2, v).
type Response struct {
	Z1 *num.Int `cbor:"z1"`
	Z2 *num.Int `cbor:"z2"`
	W1 *num.Int `cbor:"w1"`
	W2 *num.Int `cbor:"w2"`
	V  *num.Int `cbor:"v"`
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	if r == nil {
		return nil
	}

	out := binary.LittleEndian.AppendUint64(nil, 5)
	for _, z := range []*num.Int{r.Z1, r.Z2, r.W1, r.W2, r.V} {
		var zBytes []byte
		if z != nil {
			zBytes = z.TwosComplementBytesBE()
		}
		out = sliceutils.AppendLengthPrefixed(out, zBytes)
	}
	return out
}

// Protocol implements the CGGMP21 small-factor proof from Figure 26.
type Protocol struct {
	name            sigma.Name
	ringPedersenKey *intcom.CommitmentKey
	l               int
	epsilon         int
	challengeBytes  int
	prng            io.Reader
}

// NewProtocol constructs a CGGMP21 small-factor proof instance.
//
// The commitment key is the auxiliary Pedersen setup (Nhat, s, t) from
// Figure 26.
//
// The range parameter is ell from Figure 26 and must provide at least 128 bits
// of soundness for Fiat-Shamir use. The slack parameter is epsilon; this
// implementation requires epsilon >= 2*ell so that the documented response
// bounds contain honest transcripts for the full factor range.
func NewProtocol(commitmentKey *intcom.CommitmentKey, rangeBits, slackBits int, prng io.Reader) (*Protocol, error) {
	if err := validateCommitmentKey(commitmentKey); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid commitment key")
	}
	if rangeBits%8 != 0 || slackBits%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("rangeBits and slackBits must be byte-aligned")
	}
	ringPedersenCommitmentKeyBitLen := commitmentKey.Group().Modulus().TrueLen()
	if ringPedersenCommitmentKeyBitLen%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("commitment key modulus bit length must be byte-aligned")
	}
	if rangeBits < base.ComputationalSecurityBits || (4*rangeBits) >= ringPedersenCommitmentKeyBitLen {
		return nil, ErrInvalidArgument.WithMessage("rangeBits out of range")
	}
	if slackBits < 2*rangeBits || slackBits > ringPedersenCommitmentKeyBitLen {
		return nil, ErrInvalidArgument.WithMessage("slackBits out of range")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng must not be nil")
	}

	return &Protocol{
		name:            sigma.Name(fmt.Sprintf("%s_L=%d_EPS=%d_CK=%s", Name, rangeBits, slackBits, commitmentKeyDigest(commitmentKey))),
		ringPedersenKey: commitmentKey,
		l:               rangeBits,
		epsilon:         slackBits,
		challengeBytes:  rangeBits / 8,
		prng:            prng,
	}, nil
}

// Name returns the protocol identifier.
func (p *Protocol) Name() sigma.Name {
	return p.name
}

// ComputeProverCommitment generates the first prover message.
func (p *Protocol) ComputeProverCommitment(statement *Statement, witness *Witness) (*Commitment, *State, error) {
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement or witness")
	}

	state, err := p.sampleState(statement)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample prover state")
	}
	commitment, err := p.computeCommitment(witness, state)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute prover commitment")
	}
	return commitment, state, nil
}

// ComputeProverResponse generates the prover response for a fixed challenge.
func (p *Protocol) ComputeProverResponse(
	statement *Statement,
	witness *Witness,
	commitment *Commitment,
	state *State,
	challenge sigma.ChallengeBytes,
) (*Response, error) {
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid statement or witness")
	}
	if err := p.validateCommitment(commitment); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid commitment")
	}
	if err := validateState(state); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid state")
	}
	expected, err := p.computeCommitment(witness, state)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute expected commitment")
	}
	if !commitment.Equal(expected) {
		return nil, ErrValidationFailed.WithMessage("commitment and state mismatch")
	}
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	pFactor, qFactor, err := paillierKeyFactors(witness.SecretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not extract witness factors")
	}
	response := &Response{
		Z1: state.Alpha.Add(e.Mul(pFactor)),
		Z2: state.Beta.Add(e.Mul(qFactor)),
		W1: state.X.Add(e.Mul(state.Mu)),
		W2: state.Y.Add(e.Mul(state.Nu)),
		V:  state.R.Sub(e.Mul(state.Nu).Mul(pFactor)),
	}
	return response, nil
}

// Verify checks a prover response against the statement and commitment.
func (p *Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	if err := p.validateStatement(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := p.validateCommitment(commitment); err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment")
	}
	if err := p.validateResponse(response); err != nil {
		return errs.Wrap(err).WithMessage("invalid response")
	}
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid challenge")
	}

	zBitLenBound := statement.PublicKey.PlaintextGroup().Modulus().TrueLen()/2 + p.l + p.epsilon
	if !intInSignedBitRange(response.Z1, zBitLenBound) || !intInSignedBitRange(response.Z2, zBitLenBound) {
		return ErrVerificationFailed.WithMessage("factor responses are out of range")
	}

	pe, err := p.ringPedersenKey.CommitmentScalarOp(commitment.P, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not exponentiate P commitment")
	}
	firstCommitment, err := p.ringPedersenKey.CommitmentOp(commitment.A, pe)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute first verification commitment")
	}
	z1Message, err := intcom.NewMessage(response.Z1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create first verification message")
	}
	w1Witness, err := intcom.NewWitness(response.W1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create first verification witness")
	}
	if err := p.ringPedersenKey.Open(firstCommitment, z1Message, w1Witness); err != nil {
		return errs.Join(ErrVerificationFailed.WithStackFrame(), errs.Wrap(err).WithMessage("first commitment equation failed"))
	}

	qe, err := p.ringPedersenKey.CommitmentScalarOp(commitment.Q, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not exponentiate Q commitment")
	}
	secondCommitment, err := p.ringPedersenKey.CommitmentOp(commitment.B, qe)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute second verification commitment")
	}
	z2Message, err := intcom.NewMessage(response.Z2)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create second verification message")
	}
	w2Witness, err := intcom.NewWitness(response.W2)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create second verification witness")
	}
	if err := p.ringPedersenKey.Open(secondCommitment, z2Message, w2Witness); err != nil {
		return errs.Join(ErrVerificationFailed.WithStackFrame(), errs.Wrap(err).WithMessage("second commitment equation failed"))
	}

	qz1, err := p.ringPedersenKey.CommitmentScalarOp(commitment.Q, response.Z1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not exponentiate Q by z1")
	}
	qz1Inv, err := p.ringPedersenKey.CommitmentOpInv(qz1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not invert Q to the z1")
	}
	modulusCommitment, err := p.commit(statement.PublicKey.Group().N().Lift(), num.Z().Zero())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute statement modulus commitment")
	}
	modulusCommitmentE, err := p.ringPedersenKey.CommitmentScalarOp(modulusCommitment, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not exponentiate statement modulus commitment")
	}
	productCommitment, err := p.ringPedersenKey.CommitmentOp(commitment.T, modulusCommitmentE, qz1Inv)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute product verification commitment")
	}
	zeroMessage, err := intcom.NewMessage(num.Z().Zero())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create product verification message")
	}
	vWitness, err := intcom.NewWitness(response.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create product verification witness")
	}
	if err := p.ringPedersenKey.Open(productCommitment, zeroMessage, vWitness); err != nil {
		return errs.Join(ErrVerificationFailed.WithStackFrame(), errs.Wrap(err).WithMessage("product commitment equation failed"))
	}

	return nil
}

// RunSimulator creates an honest-verifier simulated transcript for a fixed challenge.
func (p *Protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	if err := p.validateStatement(statement); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	zBitLenBound := statement.PublicKey.PlaintextGroup().Modulus().TrueLen()/2 + p.l + p.epsilon
	wBitLenBound := p.ringPedersenKey.Group().Modulus().TrueLen() + p.l + p.epsilon
	vBitLenBound := statement.PublicKey.PlaintextGroup().Modulus().TrueLen() + p.ringPedersenKey.Group().Modulus().TrueLen() + p.l + p.epsilon
	sigmaBitLenBound := statement.PublicKey.PlaintextGroup().Modulus().TrueLen() + p.ringPedersenKey.Group().Modulus().TrueLen() + p.l

	sigmaP, err := intSampleRangeSymmetricBits(sigmaBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample P exponent")
	}
	sigmaQ, err := intSampleRangeSymmetricBits(sigmaBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample Q exponent")
	}

	response := &Response{}
	response.Z1, err = intSampleRangeSymmetricBits(zBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z1")
	}
	response.Z2, err = intSampleRangeSymmetricBits(zBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z2")
	}
	response.W1, err = intSampleRangeSymmetricBits(wBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample w1")
	}
	response.W2, err = intSampleRangeSymmetricBits(wBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample w2")
	}
	response.V, err = intSampleRangeSymmetricBits(vBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample v")
	}

	commitment := &Commitment{}
	commitment.P, err = p.commit(num.Z().Zero(), sigmaP)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated P")
	}
	commitment.Q, err = p.commit(num.Z().Zero(), sigmaQ)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated Q")
	}

	eNeg := e.Neg()
	z1Commitment, err := p.commit(response.Z1, response.W1)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated A response commitment")
	}
	pNegE, err := p.ringPedersenKey.CommitmentScalarOp(commitment.P, eNeg)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not exponentiate simulated P")
	}
	commitment.A, err = p.ringPedersenKey.CommitmentOp(z1Commitment, pNegE)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated A")
	}

	z2Commitment, err := p.commit(response.Z2, response.W2)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated B response commitment")
	}
	qNegE, err := p.ringPedersenKey.CommitmentScalarOp(commitment.Q, eNeg)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not exponentiate simulated Q")
	}
	commitment.B, err = p.ringPedersenKey.CommitmentOp(z2Commitment, qNegE)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated B")
	}

	qz1, err := p.ringPedersenKey.CommitmentScalarOp(commitment.Q, response.Z1)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not exponentiate simulated Q by z1")
	}
	tv, err := p.commit(num.Z().Zero(), response.V)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated product randomness commitment")
	}
	modulusCommitment, err := p.commit(statement.PublicKey.Group().N().Lift(), num.Z().Zero())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute statement modulus commitment")
	}
	modulusNegE, err := p.ringPedersenKey.CommitmentScalarOp(modulusCommitment, eNeg)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not exponentiate statement modulus commitment")
	}
	commitment.T, err = p.ringPedersenKey.CommitmentOp(qz1, tv, modulusNegE)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated T")
	}

	return commitment, response, nil
}

// SpecialSoundness returns the protocol extraction parameter.
func (*Protocol) SpecialSoundness() uint {
	return 2
}

// SoundnessError returns the statistical soundness error in bits.
func (p *Protocol) SoundnessError() uint {
	return uint(p.l)
}

// GetChallengeBytesLength returns the challenge size in bytes.
func (p *Protocol) GetChallengeBytesLength() int {
	return p.challengeBytes
}

// ValidateStatement checks that the public modulus and witness factors match.
func (p *Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if err := p.validateStatement(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := p.validateWitness(statement, witness); err != nil {
		return errs.Wrap(err).WithMessage("invalid witness")
	}
	return nil
}

func (p *Protocol) sampleState(statement *Statement) (*State, error) {
	nDashBitLen := p.ringPedersenKey.Group().Modulus().TrueLen()
	n0BitLen := statement.PublicKey.PlaintextGroup().Modulus().TrueLen()

	alpha, err := intSampleRangeSymmetricBits(p.l+p.epsilon+n0BitLen/2, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample alpha")
	}
	beta, err := intSampleRangeSymmetricBits(p.l+p.epsilon+n0BitLen/2, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample beta")
	}
	mu, err := intSampleRangeSymmetricBits(p.l+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample mu")
	}
	nu, err := intSampleRangeSymmetricBits(p.l+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample nu")
	}
	r, err := intSampleRangeSymmetricBits(p.l+p.epsilon+n0BitLen+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample r")
	}
	x, err := intSampleRangeSymmetricBits(p.l+p.epsilon+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample x")
	}
	y, err := intSampleRangeSymmetricBits(p.l+p.epsilon+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample y")
	}

	state := &State{
		Alpha: alpha,
		Beta:  beta,
		Mu:    mu,
		Nu:    nu,
		R:     r,
		X:     x,
		Y:     y,
	}
	return state, nil
}

func (p *Protocol) computeCommitment(witness *Witness, state *State) (*Commitment, error) {
	pInt, qInt, err := paillierKeyFactors(witness.SecretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not extract witness factors")
	}
	pCommitment, err := p.commit(pInt, state.Mu)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute P commitment")
	}
	qCommitment, err := p.commit(qInt, state.Nu)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute Q commitment")
	}
	aCommitment, err := p.commit(state.Alpha, state.X)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute A commitment")
	}
	bCommitment, err := p.commit(state.Beta, state.Y)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute B commitment")
	}
	qAlpha, err := p.ringPedersenKey.CommitmentScalarOp(qCommitment, state.Alpha)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not exponentiate Q commitment")
	}
	tR, err := p.commit(num.Z().Zero(), state.R)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute T randomness commitment")
	}
	tCommitment, err := p.ringPedersenKey.CommitmentOp(qAlpha, tR)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute T commitment")
	}

	return &Commitment{
		P: pCommitment,
		Q: qCommitment,
		A: aCommitment,
		B: bCommitment,
		T: tCommitment,
	}, nil
}

func (p *Protocol) commit(messageValue, witnessValue *num.Int) (*intcom.Commitment, error) {
	message, err := intcom.NewMessage(messageValue)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment message")
	}
	witness, err := intcom.NewWitness(witnessValue)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment witness")
	}
	commitment, err := p.ringPedersenKey.CommitWithWitness(message, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not commit")
	}
	return commitment, nil
}

func (p *Protocol) mapChallenge(challenge sigma.ChallengeBytes) (*num.Int, error) {
	if len(challenge) != p.challengeBytes {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	// Fiat-Shamir supplies exactly ell bits. Interpreting those bytes as a
	// signed integer gives a byte-aligned challenge space of cardinality 2^ell.
	out, err := num.Z().FromTwosComplementBytesBE(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not parse challenge")
	}
	return out, nil
}

func validatePublicKey(statement *Statement) error {
	if statement == nil || statement.PublicKey == nil || statement.PublicKey.Group() == nil {
		return ErrInvalidArgument.WithMessage("public key must not be nil")
	}
	if statement.PublicKey.PlaintextGroup().Modulus().TrueLen()%8 != 0 {
		return ErrValidationFailed.WithMessage("public key modulus bit length must be byte-aligned")
	}
	return nil
}

func (p *Protocol) validateStatement(statement *Statement) error {
	if err := validatePublicKey(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid public key")
	}
	if statement.PublicKey.PlaintextGroup().Modulus().TrueLen() <= 4*p.l {
		return ErrValidationFailed.WithMessage("public key modulus too small")
	}
	return nil
}

func validateCommitmentKey(commitmentKey *intcom.CommitmentKey) error {
	if commitmentKey == nil {
		return ErrInvalidArgument.WithMessage("commitment key must not be nil")
	}
	s := commitmentKey.S()
	t := commitmentKey.T()
	if s == nil || t == nil {
		return ErrInvalidArgument.WithMessage("s and t must not be nil")
	}
	group := s.Group()
	if !group.Contains(t) {
		return ErrValidationFailed.WithMessage("s and t must belong to the same RSA group")
	}
	if s.Equal(t) {
		return ErrValidationFailed.WithMessage("s and t must be distinct")
	}
	if s.IsOne() || t.IsOne() {
		return ErrValidationFailed.WithMessage("s and t must not be the identity")
	}
	if !s.IsTorsionFree() || !t.IsTorsionFree() {
		return ErrValidationFailed.WithMessage("s and t must be torsion-free")
	}
	if !s.Value().Decrement().Nat().Coprime(s.Modulus().Nat()) {
		return ErrValidationFailed.WithMessage("s cannot be a generator of QR(N)")
	}
	if !t.Value().Decrement().Nat().Coprime(t.Modulus().Nat()) {
		return ErrValidationFailed.WithMessage("t cannot be a generator of QR(N)")
	}
	return nil
}

func (*Protocol) validateWitness(statement *Statement, witness *Witness) error {
	if witness == nil || witness.SecretKey == nil {
		return ErrInvalidArgument.WithMessage("secret key must not be nil")
	}
	if witness.SecretKey.Group() == nil {
		return ErrInvalidArgument.WithMessage("secret key group must not be nil")
	}
	if !witness.SecretKey.Public().Equal(statement.PublicKey) {
		return ErrValidationFailed.WithMessage("secret key does not match statement")
	}

	pFactor, qFactor, err := paillierKeyFactors(witness.SecretKey)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not extract witness factors")
	}
	product, err := num.NPlus().FromNat(pFactor.Abs().Mul(qFactor.Abs()))
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute factor product")
	}
	if !product.Equal(statement.PublicKey.Group().N()) {
		return ErrValidationFailed.WithMessage("p and q do not factor the statement modulus")
	}

	// paillier.SecretKey wraps a known-order Paillier group whose factors have
	// equal bit length. Once p*q=N0 is checked, that balanced shape satisfies
	// Figure 26's |p|,|q| < sqrt(N0)*2^ell factor bound for this protocol's ell.
	return nil
}

func (p *Protocol) validateCommitment(commitment *Commitment) error {
	if commitment == nil {
		return ErrInvalidArgument.WithMessage("commitment must not be nil")
	}
	group := p.ringPedersenKey.CommitmentGroup()
	for _, elem := range []*intcom.Commitment{commitment.P, commitment.Q, commitment.A, commitment.B, commitment.T} {
		if elem == nil {
			return ErrInvalidArgument.WithMessage("commitment element must not be nil")
		}
		if elem.Value() == nil {
			return ErrInvalidArgument.WithMessage("commitment value must not be nil")
		}
		if !group.Contains(elem.Value()) {
			return ErrValidationFailed.WithMessage("commitment element is not in the statement group")
		}
	}
	return nil
}

func validateState(state *State) error {
	if state == nil ||
		state.Alpha == nil ||
		state.Beta == nil ||
		state.Mu == nil ||
		state.Nu == nil ||
		state.R == nil ||
		state.X == nil ||
		state.Y == nil {

		return ErrInvalidArgument.WithMessage("state values must not be nil")
	}
	return nil
}

func (*Protocol) validateResponse(response *Response) error {
	if response == nil ||
		response.Z1 == nil ||
		response.Z2 == nil ||
		response.W1 == nil ||
		response.W2 == nil ||
		response.V == nil {

		return ErrInvalidArgument.WithMessage("response values must not be nil")
	}

	return nil
}
