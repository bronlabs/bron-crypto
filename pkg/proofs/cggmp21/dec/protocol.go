package dec

import (
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	challengeBitsLength  = base.ComputationalSecurityBits
	challengeBytesLength = base.ComputationalSecurityBytesCeil
)

// Protocol implements the CGGMP21 Paillier special decryption in the exponent proof from Figure 28.
type Protocol[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	name    sigma.Name
	l       int
	lPrime  int
	epsilon int
	curve   ecdsa.Curve[G, B, S]
	prng    io.Reader
}

// NewProtocol constructs the CGGMP21 Figure 28 Paillier special decryption sigma protocol.
func NewProtocol[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](l, lPrime, epsilon int, curve ecdsa.Curve[G, B, S], prng io.Reader) (*Protocol[G, B, S], error) {
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng is required")
	}
	if utils.IsNil(curve) {
		return nil, ErrInvalidArgument.WithMessage("curve is required")
	}
	if (l <= 0) || (l%8 != 0) {
		return nil, ErrInvalidArgument.WithMessage("l must be a multiple of 8")
	}
	if (lPrime <= 0) || (lPrime%8 != 0) {
		return nil, ErrInvalidArgument.WithMessage("lPrime must be a multiple of 8")
	}
	if (epsilon <= 0) || (epsilon%8 != 0) {
		return nil, ErrInvalidArgument.WithMessage("epsilon must be a multiple of 8")
	}

	k := curve.ScalarField().BitLen()
	if k < base.ComputationalSecurityBits {
		return nil, ErrInvalidArgument.WithMessage("invalid curve")
	}
	if l < k {
		return nil, ErrInvalidArgument.WithMessage("invalid l")
	}
	if epsilon < l+k {
		return nil, ErrInvalidArgument.WithMessage("invalid epsilon")
	}
	if lPrime < l+epsilon+2*l {
		return nil, ErrInvalidArgument.WithMessage("invalid lPrime")
	}

	name := sigma.Name(fmt.Sprintf(
		"%s_L=%d_LPRIME=%d_EPS=%d_CURVE=%s_KAPPA=%d",
		Name,
		l,
		lPrime,
		epsilon,
		curve.Name(),
		challengeBitsLength,
	))
	p := &Protocol[G, B, S]{
		name:    name,
		l:       l,
		lPrime:  lPrime,
		epsilon: epsilon,
		curve:   curve,
		prng:    prng,
	}
	return p, nil
}

// Name returns the protocol identifier, including public parameters.
func (p *Protocol[G, B, S]) Name() sigma.Name {
	return p.name
}

// ComputeProverCommitment generates the prover's first message.
func (p *Protocol[G, B, S]) ComputeProverCommitment(statement *Statement[G, B, S], witness *Witness) (*Commitment[G, B, S], *State, error) {
	if statement == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if witness == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("witness must not be nil")
	}
	if err := p.validateStatement(statement); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement")
	}

	state, err := p.sampleState(statement)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample prover state")
	}
	commitment, err := p.computeCommitment(statement, state)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute prover commitment")
	}
	return commitment, state, nil
}

// ComputeProverResponse generates the prover response for a fixed challenge.
func (p *Protocol[G, B, S]) ComputeProverResponse(statement *Statement[G, B, S], witness *Witness, commitment *Commitment[G, B, S], state *State, challenge sigma.ChallengeBytes) (*Response, error) {
	if statement == nil {
		return nil, ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if witness == nil {
		return nil, ErrInvalidArgument.WithMessage("witness must not be nil")
	}
	if commitment == nil {
		return nil, ErrInvalidArgument.WithMessage("commitment must not be nil")
	}
	if state == nil {
		return nil, ErrInvalidArgument.WithMessage("state must not be nil")
	}
	if err := p.validateStatement(statement); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	bits, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	z := make([]*num.Int, challengeBitsLength)
	w := make([]*num.Int, challengeBitsLength)
	nu := make([]*paillier.Nonce, challengeBitsLength)
	for i, bit := range bits {
		e := bitToInt(bit)
		z[i] = state.alpha[i].Add(e.Mul(witness.x))
		w[i] = state.beta[i].Add(e.Mul(witness.y))
		nu[i] = state.r[i]
		if bit == 1 {
			nu[i], err = statement.n0.NonceOp(state.r[i], witness.rho)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("could not compute nu at index %d", i)
			}
		}
	}

	response, err := NewResponse(z, w, nu)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return response, nil
}

// Verify checks the Figure 28 equality checks and widened response ranges.
func (p *Protocol[G, B, S]) Verify(statement *Statement[G, B, S], commitment *Commitment[G, B, S], challenge sigma.ChallengeBytes, response *Response) error {
	if statement == nil {
		return ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if commitment == nil {
		return ErrInvalidArgument.WithMessage("commitment must not be nil")
	}
	if response == nil {
		return ErrInvalidArgument.WithMessage("response must not be nil")
	}
	if err := p.validateStatement(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := p.validateCommitment(statement, commitment); err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment")
	}
	if err := p.validateResponse(statement, response); err != nil {
		return errs.Wrap(err).WithMessage("invalid response")
	}
	bits, err := p.mapChallenge(challenge)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid challenge")
	}

	for i := range bits {
		if !intInSignedBitRange(response.z[i], p.l+p.epsilon) {
			return ErrVerificationFailed.WithMessage("z is out of range at index %d", i)
		}
		if !intInSignedBitRange(response.w[i], p.lPrime+p.epsilon) {
			return ErrVerificationFailed.WithMessage("w is out of range at index %d", i)
		}
	}

	wPlaintexts, err := intsToPlaintexts(response.w, statement.n0)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create w plaintexts")
	}
	encW, err := encryption.EncryptManyWithNonces(wPlaintexts, statement.n0, response.nu)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not encrypt w values under N0")
	}

	for i, bit := range bits {
		if err := p.verifyPaillier(statement, commitment, response, encW[i], bit, i); err != nil {
			return errs.Wrap(err).WithMessage("Paillier equality failed at index %d", i)
		}
		if err := p.verifyCurve(statement, commitment, response, bit, i); err != nil {
			return errs.Wrap(err).WithMessage("curve equality failed at index %d", i)
		}
	}
	return nil
}

// RunSimulator creates an honest-verifier simulated transcript for a fixed challenge.
func (p *Protocol[G, B, S]) RunSimulator(statement *Statement[G, B, S], challenge sigma.ChallengeBytes) (*Commitment[G, B, S], *Response, error) {
	if statement == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if err := p.validateStatement(statement); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	bits, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	z := make([]*num.Int, challengeBitsLength)
	w := make([]*num.Int, challengeBitsLength)
	nu := make([]*paillier.Nonce, challengeBitsLength)
	for i := range challengeBitsLength {
		z[i], err = intSampleRangeSymmetricBits(p.l+p.epsilon, p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample z at index %d", i)
		}
		w[i], err = intSampleRangeSymmetricBits(p.lPrime+p.epsilon, p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample w at index %d", i)
		}
		nu[i], err = statement.n0.SampleNonce(p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample nu at index %d", i)
		}
	}
	response, err := NewResponse(z, w, nu)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create response")
	}

	a, err := p.simulateA(statement, response, bits)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated A")
	}
	b, err := p.simulateB(statement, response, bits)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated B")
	}
	c, err := p.simulateC(statement, response, bits)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated C")
	}
	commitment, err := NewCommitment(a, b, c)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	return commitment, response, nil
}

// SpecialSoundness returns the protocol extraction parameter.
func (*Protocol[G, B, S]) SpecialSoundness() uint {
	return 2
}

// SoundnessError returns the kappa-bit soundness error.
func (*Protocol[G, B, S]) SoundnessError() uint {
	return uint(challengeBitsLength)
}

// GetChallengeBytesLength returns the challenge size in bytes.
func (*Protocol[G, B, S]) GetChallengeBytesLength() int {
	return challengeBytesLength
}

// ValidateStatement checks that the witness opens the public statement and lies in the configured ranges.
func (p *Protocol[G, B, S]) ValidateStatement(statement *Statement[G, B, S], witness *Witness) error {
	if statement == nil {
		return ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if witness == nil {
		return ErrInvalidArgument.WithMessage("witness must not be nil")
	}
	if err := p.validateStatement(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := p.validateWitness(statement, witness); err != nil {
		return errs.Wrap(err).WithMessage("invalid witness")
	}
	return nil
}

func (p *Protocol[G, B, S]) sampleState(statement *Statement[G, B, S]) (*State, error) {
	alpha := make([]*num.Int, challengeBitsLength)
	beta := make([]*num.Int, challengeBitsLength)
	r := make([]*paillier.Nonce, challengeBitsLength)
	for i := range challengeBitsLength {
		var err error
		alpha[i], err = intSampleRangeSymmetricBits(p.l+p.epsilon, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not sample alpha at index %d", i)
		}
		beta[i], err = intSampleRangeSymmetricBits(p.lPrime+p.epsilon, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not sample beta at index %d", i)
		}
		r[i], err = statement.n0.SampleNonce(p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not sample r at index %d", i)
		}
	}

	state, err := NewState(alpha, beta, r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create state")
	}
	return state, nil
}

func (p *Protocol[G, B, S]) computeCommitment(statement *Statement[G, B, S], state *State) (*Commitment[G, B, S], error) {
	betaPlaintexts, err := intsToPlaintexts(state.beta, statement.n0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create beta plaintexts")
	}
	encBeta, err := encryption.EncryptManyWithNonces(betaPlaintexts, statement.n0, state.r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt beta values")
	}

	a := make([]*paillier.Ciphertext, challengeBitsLength)
	b := make([]G, challengeBitsLength)
	c := make([]G, challengeBitsLength)
	for i := range challengeBitsLength {
		kNegAlpha, err := statement.n0.CiphertextScalarOp(statement.k, state.alpha[i].Neg())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute K^-alpha at index %d", i)
		}
		a[i], err = statement.n0.CiphertextOp(kNegAlpha, encBeta[i])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute A at index %d", i)
		}
		betaScalar, err := intToScalar(state.beta[i], p.curve.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not convert beta to scalar at index %d", i)
		}
		b[i] = p.curve.ScalarBaseMul(betaScalar)
		alphaScalar, err := intToScalar(state.alpha[i], p.curve.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not convert alpha to scalar at index %d", i)
		}
		c[i] = p.curve.ScalarBaseMul(alphaScalar)
	}

	commitment, err := NewCommitment(a, b, c)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	return commitment, nil
}

func (*Protocol[G, B, S]) verifyPaillier(statement *Statement[G, B, S], commitment *Commitment[G, B, S], response *Response, encW *paillier.Ciphertext, bit byte, index int) error {
	kNegZ, err := statement.n0.CiphertextScalarOp(statement.k, response.z[index].Neg())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute K^-z")
	}
	left, err := statement.n0.CiphertextOp(encW, kNegZ)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Paillier left side")
	}
	right := commitment.a[index]
	if bit == 1 {
		right, err = statement.n0.CiphertextOp(right, statement.d)
		if err != nil {
			return errs.Wrap(err).WithMessage("could not compute Paillier right side")
		}
	}
	if !left.Equal(right) {
		return ErrVerificationFailed.WithMessage("Paillier equality check failed")
	}
	return nil
}

func (p *Protocol[G, B, S]) verifyCurve(statement *Statement[G, B, S], commitment *Commitment[G, B, S], response *Response, bit byte, index int) error {
	zScalar, err := intToScalar(response.z[index], p.curve.ScalarField())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not convert z to scalar")
	}
	wScalar, err := intToScalar(response.w[index], p.curve.ScalarField())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not convert w to scalar")
	}

	leftX := p.curve.ScalarBaseMul(zScalar)
	rightX := commitment.c[index]
	if bit == 1 {
		rightX = rightX.Op(statement.x)
	}
	if !leftX.Equal(rightX) {
		return ErrVerificationFailed.WithMessage("X equality check failed")
	}

	leftS := p.curve.ScalarBaseMul(wScalar)
	rightS := commitment.b[index]
	if bit == 1 {
		rightS = rightS.Op(statement.s)
	}
	if !leftS.Equal(rightS) {
		return ErrVerificationFailed.WithMessage("S equality check failed")
	}
	return nil
}

func (*Protocol[G, B, S]) simulateA(statement *Statement[G, B, S], response *Response, bits []byte) ([]*paillier.Ciphertext, error) {
	wPlaintexts, err := intsToPlaintexts(response.w, statement.n0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create w plaintexts")
	}
	encW, err := encryption.EncryptManyWithNonces(wPlaintexts, statement.n0, response.nu)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt w values")
	}

	dInv, err := statement.n0.CiphertextOpInv(statement.d)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not invert D")
	}
	out := make([]*paillier.Ciphertext, challengeBitsLength)
	for i, bit := range bits {
		kNegZ, err := statement.n0.CiphertextScalarOp(statement.k, response.z[i].Neg())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute K^-z at index %d", i)
		}
		out[i], err = statement.n0.CiphertextOp(encW[i], kNegZ)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute response side at index %d", i)
		}
		if bit == 1 {
			out[i], err = statement.n0.CiphertextOp(out[i], dInv)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("could not compute A at index %d", i)
			}
		}
	}
	return out, nil
}

func (p *Protocol[G, B, S]) simulateB(statement *Statement[G, B, S], response *Response, bits []byte) ([]G, error) {
	out := make([]G, challengeBitsLength)
	sInv := statement.s.OpInv()
	for i, bit := range bits {
		wScalar, err := intToScalar(response.w[i], p.curve.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not convert w to scalar at index %d", i)
		}
		out[i] = p.curve.ScalarBaseMul(wScalar)
		if bit == 1 {
			out[i] = out[i].Op(sInv)
		}
	}
	return out, nil
}

func (p *Protocol[G, B, S]) simulateC(statement *Statement[G, B, S], response *Response, bits []byte) ([]G, error) {
	out := make([]G, challengeBitsLength)
	xInv := statement.x.OpInv()
	for i, bit := range bits {
		zScalar, err := intToScalar(response.z[i], p.curve.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not convert z to scalar at index %d", i)
		}
		out[i] = p.curve.ScalarBaseMul(zScalar)
		if bit == 1 {
			out[i] = out[i].Op(xInv)
		}
	}
	return out, nil
}

func (*Protocol[G, B, S]) mapChallenge(challenge sigma.ChallengeBytes) ([]byte, error) {
	if len(challenge) != challengeBytesLength {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	out := make([]byte, challengeBitsLength)
	for i := range challengeBitsLength {
		out[i] = (challenge[i/8] >> uint(7-(i%8))) & 1
	}
	return out, nil
}

func (p *Protocol[G, B, S]) validateStatement(statement *Statement[G, B, S]) error {
	if statement.n0.PlaintextGroup().Modulus().TrueLen()%8 != 0 {
		return ErrValidationFailed.WithMessage("Paillier modulus bit length must be byte-aligned")
	}
	if err := signedBoundFitsPaillier(p.lPrime+p.epsilon, statement.n0); err != nil {
		return errs.Wrap(err).WithMessage("invalid N0 modulus for w response range")
	}
	if !statement.n0.CiphertextGroup().Contains(statement.k.Value()) ||
		!statement.n0.CiphertextGroup().Contains(statement.d.Value()) {

		return ErrValidationFailed.WithMessage("K and D must be in the N0 ciphertext group")
	}
	if !p.curve.Contains(statement.x) || !p.curve.Contains(statement.s) {
		return ErrValidationFailed.WithMessage("X and S must be in the curve group")
	}
	return nil
}

func (p *Protocol[G, B, S]) validateWitness(statement *Statement[G, B, S], witness *Witness) error {
	if !intInSignedBitRange(witness.x, p.l) {
		return ErrValidationFailed.WithMessage("x is out of range")
	}
	if !intInSignedBitRange(witness.y, p.lPrime) {
		return ErrValidationFailed.WithMessage("y is out of range")
	}
	if !statement.n0.NonceGroup().Contains(witness.rho.Value()) {
		return ErrValidationFailed.WithMessage("rho is not in the N0 nonce group")
	}

	xScalar, err := intToScalar(witness.x, p.curve.ScalarField())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not convert x to scalar")
	}
	if !p.curve.ScalarBaseMul(xScalar).Equal(statement.x) {
		return ErrValidationFailed.WithMessage("x does not open X")
	}
	yScalar, err := intToScalar(witness.y, p.curve.ScalarField())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not convert y to scalar")
	}
	if !p.curve.ScalarBaseMul(yScalar).Equal(statement.s) {
		return ErrValidationFailed.WithMessage("y does not open S")
	}

	yPlaintext, err := intToPlaintext(witness.y, statement.n0)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create y plaintext")
	}
	encY, err := statement.n0.EncryptWithNonce(yPlaintext, witness.rho)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not encrypt y")
	}
	kX, err := statement.n0.CiphertextScalarOp(statement.k, witness.x)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute K^x")
	}
	right, err := statement.n0.CiphertextOp(kX, statement.d)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute K^x D")
	}
	if !encY.Equal(right) {
		return ErrValidationFailed.WithMessage("witness does not open Paillier relation")
	}
	return nil
}

func (p *Protocol[G, B, S]) validateCommitment(statement *Statement[G, B, S], commitment *Commitment[G, B, S]) error {
	for i := range challengeBitsLength {
		if !statement.n0.CiphertextGroup().Contains(commitment.a[i].Value()) {
			return ErrValidationFailed.WithMessage("A must be in the N0 ciphertext group at index %d", i)
		}
		if !p.curve.Contains(commitment.b[i]) {
			return ErrValidationFailed.WithMessage("B must be in the curve group at index %d", i)
		}
		if !p.curve.Contains(commitment.c[i]) {
			return ErrValidationFailed.WithMessage("C must be in the curve group at index %d", i)
		}
	}
	return nil
}

func (*Protocol[G, B, S]) validateResponse(statement *Statement[G, B, S], response *Response) error {
	for i := range challengeBitsLength {
		if !statement.n0.NonceGroup().Contains(response.nu[i].Value()) {
			return ErrValidationFailed.WithMessage("nu must be in the N0 nonce group at index %d", i)
		}
	}
	return nil
}

func bitToInt(bit byte) *num.Int {
	if bit == 0 {
		return num.Z().Zero()
	}
	return num.Z().One()
}
