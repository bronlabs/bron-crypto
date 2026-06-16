package affgstar

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

// Protocol implements the CGGMP21 setup-less Paillier affine operation with group commitment proof from Figure 27.
type Protocol[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	name    sigma.Name
	l       int
	lPrime  int
	epsilon int
	curve   ecdsa.Curve[G, B, S]
	prng    io.Reader
}

// NewProtocol constructs the CGGMP21 Figure 27 setup-less Paillier affine sigma protocol.
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

	y := witness.y.Normalise()
	z := make([]*num.Int, challengeBitsLength)
	zPrime := make([]*num.Int, challengeBitsLength)
	w := make([]*paillier.Nonce, challengeBitsLength)
	lambda := make([]*paillier.Nonce, challengeBitsLength)
	for i, bit := range bits {
		e := bitToInt(bit)
		z[i] = state.alpha[i].Add(e.Mul(witness.x))
		zPrime[i] = state.beta[i].Add(e.Mul(y))
		rhoE, err := statement.n0.NonceScalarOp(witness.rho, e)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute rho^e at index %d", i)
		}
		w[i], err = statement.n0.NonceOp(state.r[i], rhoE)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute w at index %d", i)
		}
		rhoYE, err := statement.n1.NonceScalarOp(witness.rhoY, e)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute rhoY^e at index %d", i)
		}
		lambda[i], err = statement.n1.NonceOp(state.s[i], rhoYE)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute lambda at index %d", i)
		}
	}

	response, err := NewResponse(z, zPrime, w, lambda)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return response, nil
}

// Verify checks the Figure 27 equality checks and widened response ranges.
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
		if !intInSignedBitRange(response.zPrime[i], p.lPrime+p.epsilon) {
			return ErrVerificationFailed.WithMessage("zPrime is out of range at index %d", i)
		}
	}

	zPrimeN0, err := intsToPlaintexts(response.zPrime, statement.n0)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create zPrime plaintexts for N0")
	}
	encZPrimeN0, err := encryption.EncryptManyWithNonces(zPrimeN0, statement.n0, response.w)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not encrypt zPrime values under N0")
	}
	zPrimeN1, err := intsToPlaintexts(response.zPrime, statement.n1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create zPrime plaintexts for N1")
	}
	encZPrimeN1, err := encryption.EncryptManyWithNonces(zPrimeN1, statement.n1, response.lambda)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not encrypt zPrime values under N1")
	}

	for i, bit := range bits {
		if err := p.verifyN0(statement, commitment, response, encZPrimeN0[i], bit, i); err != nil {
			return errs.Wrap(err).WithMessage("N0 equality failed at index %d", i)
		}
		if err := p.verifyCurve(statement, commitment, response, bit, i); err != nil {
			return errs.Wrap(err).WithMessage("curve equality failed at index %d", i)
		}
		if err := p.verifyN1(statement, commitment, encZPrimeN1[i], bit, i); err != nil {
			return errs.Wrap(err).WithMessage("N1 equality failed at index %d", i)
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
	zPrime := make([]*num.Int, challengeBitsLength)
	w := make([]*paillier.Nonce, challengeBitsLength)
	lambda := make([]*paillier.Nonce, challengeBitsLength)
	for i := range challengeBitsLength {
		z[i], err = intSampleRangeSymmetricBits(p.l+p.epsilon, p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample z at index %d", i)
		}
		zPrime[i], err = intSampleRangeSymmetricBits(p.lPrime+p.epsilon, p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample zPrime at index %d", i)
		}
		w[i], err = statement.n0.SampleNonce(p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample w at index %d", i)
		}
		lambda[i], err = statement.n1.SampleNonce(p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample lambda at index %d", i)
		}
	}
	response, err := NewResponse(z, zPrime, w, lambda)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create response")
	}

	a, err := p.simulateA(statement, response, bits)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated A")
	}
	r, err := p.simulateR(statement, response, bits)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated R")
	}
	b, err := p.simulateB(statement, response, bits)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated B")
	}
	commitment, err := NewCommitment(a, b, r)
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
	s := make([]*paillier.Nonce, challengeBitsLength)
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
		s[i], err = statement.n1.SampleNonce(p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not sample s at index %d", i)
		}
	}

	state, err := NewState(alpha, beta, r, s)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create state")
	}
	return state, nil
}

func (p *Protocol[G, B, S]) computeCommitment(statement *Statement[G, B, S], state *State) (*Commitment[G, B, S], error) {
	betaN0, err := intsToPlaintexts(state.beta, statement.n0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create beta plaintexts for N0")
	}
	encBetaN0, err := encryption.EncryptManyWithNonces(betaN0, statement.n0, state.r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt beta values under N0")
	}

	a := make([]*paillier.Ciphertext, challengeBitsLength)
	r := make([]G, challengeBitsLength)
	for i := range challengeBitsLength {
		cAlpha, err := statement.n0.CiphertextScalarOp(statement.c, state.alpha[i])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute C^alpha at index %d", i)
		}
		a[i], err = statement.n0.CiphertextOp(cAlpha, encBetaN0[i])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute A at index %d", i)
		}
		alphaScalar, err := intToScalar(state.alpha[i], p.curve.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not convert alpha to scalar at index %d", i)
		}
		r[i] = p.curve.ScalarBaseMul(alphaScalar)
	}

	betaN1, err := intsToPlaintexts(state.beta, statement.n1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create beta plaintexts for N1")
	}
	b, err := encryption.EncryptManyWithNonces(betaN1, statement.n1, state.s)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt beta values under N1")
	}

	commitment, err := NewCommitment(a, b, r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	return commitment, nil
}

func (*Protocol[G, B, S]) verifyN0(statement *Statement[G, B, S], commitment *Commitment[G, B, S], response *Response, encZPrime *paillier.Ciphertext, bit byte, index int) error {
	cZ, err := statement.n0.CiphertextScalarOp(statement.c, response.z[index])
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute C^z")
	}
	left, err := statement.n0.CiphertextOp(cZ, encZPrime)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute N0 left side")
	}
	right := commitment.a[index]
	if bit == 1 {
		right, err = statement.n0.CiphertextOp(right, statement.d)
		if err != nil {
			return errs.Wrap(err).WithMessage("could not compute N0 right side")
		}
	}
	if !left.Equal(right) {
		return ErrVerificationFailed.WithMessage("N0 equality check failed")
	}
	return nil
}

func (p *Protocol[G, B, S]) verifyCurve(statement *Statement[G, B, S], commitment *Commitment[G, B, S], response *Response, bit byte, index int) error {
	zScalar, err := intToScalar(response.z[index], p.curve.ScalarField())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not convert z to scalar")
	}
	left := p.curve.ScalarBaseMul(zScalar)
	right := commitment.r[index]
	if bit == 1 {
		right = right.Op(statement.x)
	}
	if !left.Equal(right) {
		return ErrVerificationFailed.WithMessage("curve equality check failed")
	}
	return nil
}

func (*Protocol[G, B, S]) verifyN1(statement *Statement[G, B, S], commitment *Commitment[G, B, S], encZPrime *paillier.Ciphertext, bit byte, index int) error {
	right := commitment.b[index]
	if bit == 1 {
		var err error
		right, err = statement.n1.CiphertextOp(right, statement.y)
		if err != nil {
			return errs.Wrap(err).WithMessage("could not compute N1 right side")
		}
	}
	if !encZPrime.Equal(right) {
		return ErrVerificationFailed.WithMessage("N1 equality check failed")
	}
	return nil
}

func (*Protocol[G, B, S]) simulateA(statement *Statement[G, B, S], response *Response, bits []byte) ([]*paillier.Ciphertext, error) {
	zPrimeN0, err := intsToPlaintexts(response.zPrime, statement.n0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create zPrime plaintexts for N0")
	}
	encZPrime, err := encryption.EncryptManyWithNonces(zPrimeN0, statement.n0, response.w)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt zPrime values under N0")
	}

	out := make([]*paillier.Ciphertext, challengeBitsLength)
	for i, bit := range bits {
		cZ, err := statement.n0.CiphertextScalarOp(statement.c, response.z[i])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute C^z at index %d", i)
		}
		left, err := statement.n0.CiphertextOp(cZ, encZPrime[i])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute response side at index %d", i)
		}
		dNegE, err := statement.n0.CiphertextScalarOp(statement.d, bitToInt(bit).Neg())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute D^-e at index %d", i)
		}
		out[i], err = statement.n0.CiphertextOp(left, dNegE)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute A at index %d", i)
		}
	}
	return out, nil
}

func (p *Protocol[G, B, S]) simulateR(statement *Statement[G, B, S], response *Response, bits []byte) ([]G, error) {
	out := make([]G, challengeBitsLength)
	for i, bit := range bits {
		zScalar, err := intToScalar(response.z[i], p.curve.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not convert z to scalar at index %d", i)
		}
		eNegScalar, err := intToScalar(bitToInt(bit).Neg(), p.curve.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not convert challenge to scalar at index %d", i)
		}
		out[i] = p.curve.ScalarBaseMul(zScalar).Op(statement.x.ScalarOp(eNegScalar))
	}
	return out, nil
}

func (*Protocol[G, B, S]) simulateB(statement *Statement[G, B, S], response *Response, bits []byte) ([]*paillier.Ciphertext, error) {
	zPrimeN1, err := intsToPlaintexts(response.zPrime, statement.n1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create zPrime plaintexts for N1")
	}
	left, err := encryption.EncryptManyWithNonces(zPrimeN1, statement.n1, response.lambda)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt zPrime values under N1")
	}

	out := make([]*paillier.Ciphertext, challengeBitsLength)
	for i, bit := range bits {
		yNegE, err := statement.n1.CiphertextScalarOp(statement.y, bitToInt(bit).Neg())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute Y^-e at index %d", i)
		}
		out[i], err = statement.n1.CiphertextOp(left[i], yNegE)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute B at index %d", i)
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
	if statement.n0.PlaintextGroup().Modulus().TrueLen()%8 != 0 || statement.n1.PlaintextGroup().Modulus().TrueLen()%8 != 0 {
		return ErrValidationFailed.WithMessage("Paillier modulus bit lengths must be byte-aligned")
	}
	if err := signedBoundFitsPaillier(p.lPrime+p.epsilon, statement.n0); err != nil {
		return errs.Wrap(err).WithMessage("invalid N0 modulus for y response range")
	}
	if err := signedBoundFitsPaillier(p.lPrime+p.epsilon, statement.n1); err != nil {
		return errs.Wrap(err).WithMessage("invalid N1 modulus for y response range")
	}
	if !statement.n0.CiphertextGroup().Contains(statement.c.Value()) ||
		!statement.n0.CiphertextGroup().Contains(statement.d.Value()) {

		return ErrValidationFailed.WithMessage("C and D must be in the N0 ciphertext group")
	}
	if !statement.n1.CiphertextGroup().Contains(statement.y.Value()) {
		return ErrValidationFailed.WithMessage("Y must be in the N1 ciphertext group")
	}
	if !p.curve.Contains(statement.x) {
		return ErrValidationFailed.WithMessage("X must be in the curve group")
	}
	return nil
}

func (p *Protocol[G, B, S]) validateWitness(statement *Statement[G, B, S], witness *Witness) error {
	if !intInSignedBitRange(witness.x, p.l) {
		return ErrValidationFailed.WithMessage("x is out of range")
	}
	y := witness.y.Normalise()
	if !intInSignedBitRange(y, p.lPrime) {
		return ErrValidationFailed.WithMessage("y is out of range")
	}
	if !statement.n1.PlaintextGroup().Contains(witness.y.Value()) {
		return ErrValidationFailed.WithMessage("y is not in the N1 plaintext group")
	}
	if !statement.n0.NonceGroup().Contains(witness.rho.Value()) {
		return ErrValidationFailed.WithMessage("rho is not in the N0 nonce group")
	}
	if !statement.n1.NonceGroup().Contains(witness.rhoY.Value()) {
		return ErrValidationFailed.WithMessage("rhoY is not in the N1 nonce group")
	}

	xScalar, err := intToScalar(witness.x, p.curve.ScalarField())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not convert x to scalar")
	}
	if !p.curve.ScalarBaseMul(xScalar).Equal(statement.x) {
		return ErrValidationFailed.WithMessage("x does not open X")
	}
	yCheck, err := statement.n1.EncryptWithNonce(witness.y, witness.rhoY)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not recompute Y")
	}
	if !statement.y.Equal(yCheck) {
		return ErrValidationFailed.WithMessage("witness does not open Y")
	}
	cX, err := statement.n0.CiphertextScalarOp(statement.c, witness.x)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute C^x")
	}
	yN0, err := intToPlaintext(y, statement.n0)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create y plaintext for N0")
	}
	encY, err := statement.n0.EncryptWithNonce(yN0, witness.rho)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not encrypt y under N0")
	}
	dCheck, err := statement.n0.CiphertextOp(cX, encY)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not recompute D")
	}
	if !statement.d.Equal(dCheck) {
		return ErrValidationFailed.WithMessage("witness does not open D")
	}
	return nil
}

func (p *Protocol[G, B, S]) validateCommitment(statement *Statement[G, B, S], commitment *Commitment[G, B, S]) error {
	for i := range challengeBitsLength {
		if !statement.n0.CiphertextGroup().Contains(commitment.a[i].Value()) {
			return ErrValidationFailed.WithMessage("A must be in the N0 ciphertext group at index %d", i)
		}
		if !statement.n1.CiphertextGroup().Contains(commitment.b[i].Value()) {
			return ErrValidationFailed.WithMessage("B must be in the N1 ciphertext group at index %d", i)
		}
		if !p.curve.Contains(commitment.r[i]) {
			return ErrValidationFailed.WithMessage("R must be in the curve group at index %d", i)
		}
	}
	return nil
}

func (*Protocol[G, B, S]) validateResponse(statement *Statement[G, B, S], response *Response) error {
	for i := range challengeBitsLength {
		if !statement.n0.NonceGroup().Contains(response.w[i].Value()) {
			return ErrValidationFailed.WithMessage("w must be in the N0 nonce group at index %d", i)
		}
		if !statement.n1.NonceGroup().Contains(response.lambda[i].Value()) {
			return ErrValidationFailed.WithMessage("lambda must be in the N1 nonce group at index %d", i)
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
