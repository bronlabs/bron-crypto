package affg

import (
	"fmt"
	"io"
	"testing"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// Protocol implements the CGGMP21 Paillier affine operation with group commitment proof from Figure 25.
type Protocol[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	name            sigma.Name
	ringPedersenKey *intcom.CommitmentKey
	l               int
	lPrime          int
	epsilon         int
	curve           ecdsa.Curve[G, B, S]
	prng            io.Reader
}

// NewProtocol constructs the CGGMP21 Figure 25 Paillier affine sigma protocol.
func NewProtocol[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ringPedersenKey *intcom.CommitmentKey, l, lPrime, epsilon int, curve ecdsa.Curve[G, B, S], prng io.Reader) (*Protocol[G, B, S], error) {
	if ringPedersenKey == nil || ringPedersenKey.Group().Modulus().TrueLen()%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("ringPedersenKey is required")
	}
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
	logN := ringPedersenKey.Group().Modulus().TrueLen()
	if logN < lPrime+epsilon {
		return nil, ErrInvalidArgument.WithMessage("invalid ring pedersen key")
	}
	if !testing.Testing() && logN < base.IFCKeyLength {
		return nil, ErrInvalidArgument.WithMessage("invalid ring pedersen key len")
	}

	name := sigma.Name(fmt.Sprintf(
		"%s_L=%d_LPRIME=%d_EPS=%d_CURVE=%s_CK=%s",
		Name,
		l,
		lPrime,
		epsilon,
		curve.Name(),
		commitmentKeyDigest(ringPedersenKey),
	))
	p := &Protocol[G, B, S]{
		name:            name,
		ringPedersenKey: ringPedersenKey,
		l:               l,
		lPrime:          lPrime,
		epsilon:         epsilon,
		curve:           curve,
		prng:            prng,
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
	commitment, err := p.computeCommitment(statement, witness, state)
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
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	y := witness.y.Normalise()
	z1 := state.alpha.Add(e.Mul(witness.x))
	z2 := state.beta.Add(e.Mul(y))
	z3 := state.gamma.Add(e.Mul(state.m))
	z4 := state.delta.Add(e.Mul(state.mu))

	rhoE, err := statement.n0.NonceScalarOp(witness.rho, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute rho^e")
	}
	w, err := statement.n0.NonceOp(state.r, rhoE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute w")
	}
	rhoYE, err := statement.n1.NonceScalarOp(witness.rhoY, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute rhoY^e")
	}
	wy, err := statement.n1.NonceOp(state.ry, rhoYE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute wy")
	}

	response, err := NewResponse(z1, z2, z3, z4, w, wy)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return response, nil
}

// Verify checks the Figure 25 equality checks and widened response ranges.
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
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid challenge")
	}

	if !intInSignedBitRange(response.z1, p.l+p.epsilon) {
		return ErrVerificationFailed.WithMessage("z1 is out of range")
	}
	if !intInSignedBitRange(response.z2, p.lPrime+p.epsilon) {
		return ErrVerificationFailed.WithMessage("z2 is out of range")
	}

	cZ1, err := statement.n0.CiphertextScalarOp(statement.c, response.z1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute C^z1")
	}
	z2N0, err := intToPlaintext(response.z2, statement.n0)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create z2 plaintext for N0")
	}
	encZ2, err := statement.n0.EncryptWithNonce(z2N0, response.w)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not encrypt z2 under N0")
	}
	leftN0, err := statement.n0.CiphertextOp(cZ1, encZ2)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute first equality left side")
	}
	dE, err := statement.n0.CiphertextScalarOp(statement.d, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute D^e")
	}
	rightN0, err := statement.n0.CiphertextOp(commitment.a, dE)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute first equality right side")
	}
	if !leftN0.Equal(rightN0) {
		return ErrVerificationFailed.WithMessage("N0 Paillier equality check failed")
	}

	z1Scalar, err := intToScalar(response.z1, p.curve.ScalarField())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not convert z1 to scalar")
	}
	eScalar, err := intToScalar(e, p.curve.ScalarField())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not convert challenge to scalar")
	}
	leftGroup := p.curve.ScalarBaseMul(z1Scalar)
	rightGroup := commitment.bx.Op(statement.x.ScalarOp(eScalar))
	if !leftGroup.Equal(rightGroup) {
		return ErrVerificationFailed.WithMessage("curve equality check failed")
	}

	z2N1, err := intToPlaintext(response.z2, statement.n1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create z2 plaintext for N1")
	}
	leftN1, err := statement.n1.EncryptWithNonce(z2N1, response.wy)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not encrypt z2 under N1")
	}
	yE, err := statement.n1.CiphertextScalarOp(statement.y, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Y^e")
	}
	rightN1, err := statement.n1.CiphertextOp(commitment.by, yE)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute N1 equality right side")
	}
	if !leftN1.Equal(rightN1) {
		return ErrVerificationFailed.WithMessage("N1 Paillier equality check failed")
	}

	z1Commitment, err := p.commit(response.z1, response.z3)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute z1 commitment")
	}
	sE, err := p.ringPedersenKey.CommitmentScalarOp(commitment.s, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute S^e")
	}
	rightE, err := p.ringPedersenKey.CommitmentOp(commitment.e, sE)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute E equality right side")
	}
	if !z1Commitment.Equal(rightE) {
		return ErrVerificationFailed.WithMessage("first Pedersen equality check failed")
	}

	z2Commitment, err := p.commit(response.z2, response.z4)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute z2 commitment")
	}
	tE, err := p.ringPedersenKey.CommitmentScalarOp(commitment.t, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute T^e")
	}
	rightF, err := p.ringPedersenKey.CommitmentOp(commitment.f, tE)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute F equality right side")
	}
	if !z2Commitment.Equal(rightF) {
		return ErrVerificationFailed.WithMessage("second Pedersen equality check failed")
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
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	nHatBitLen := p.ringPedersenKey.Group().Modulus().TrueLen()
	z1, err := intSampleRangeSymmetricBits(p.l+p.epsilon, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z1")
	}
	z2, err := intSampleRangeSymmetricBits(p.lPrime+p.epsilon, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z2")
	}
	z3, err := intSampleRangeSymmetricBits(p.l+p.epsilon+nHatBitLen, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z3")
	}
	z4, err := intSampleRangeSymmetricBits(p.lPrime+p.epsilon+nHatBitLen, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z4")
	}
	w, err := statement.n0.SampleNonce(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample w")
	}
	wy, err := statement.n1.SampleNonce(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample wy")
	}
	response, err := NewResponse(z1, z2, z3, z4, w, wy)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create response")
	}

	lambdaS, err := intSampleRangeSymmetricBits(p.l+nHatBitLen, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample S opening")
	}
	lambdaT, err := intSampleRangeSymmetricBits(p.lPrime+nHatBitLen, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample T opening")
	}
	s, err := p.commit(num.Z().Zero(), lambdaS)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated S")
	}
	t, err := p.commit(num.Z().Zero(), lambdaT)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated T")
	}

	a, err := p.simulateA(statement, response, e)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated A")
	}
	bx, err := p.simulateBX(statement, response, e)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated Bx")
	}
	by, err := p.simulateBY(statement, response, e)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated By")
	}
	eCommitment, err := p.simulatePedersen(response.z1, response.z3, s, e)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated E")
	}
	fCommitment, err := p.simulatePedersen(response.z2, response.z4, t, e)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated F")
	}

	commitment, err := NewCommitment(a, bx, by, eCommitment, fCommitment, s, t)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	return commitment, response, nil
}

// SpecialSoundness returns the protocol extraction parameter.
func (*Protocol[G, B, S]) SpecialSoundness() uint {
	return 2
}

// SoundnessError returns the challenge size in bits.
func (p *Protocol[G, B, S]) SoundnessError() uint {
	return uint(p.GetChallengeBytesLength() * 8)
}

// GetChallengeBytesLength returns the challenge size in bytes.
func (*Protocol[G, B, S]) GetChallengeBytesLength() int {
	return base.ComputationalSecurityBytesCeil
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
	nHatBitLen := p.ringPedersenKey.Group().Modulus().TrueLen()

	alpha, err := intSampleRangeSymmetricBits(p.l+p.epsilon, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample alpha")
	}
	beta, err := intSampleRangeSymmetricBits(p.lPrime+p.epsilon, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample beta")
	}
	gamma, err := intSampleRangeSymmetricBits(p.l+p.epsilon+nHatBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample gamma")
	}
	m, err := intSampleRangeSymmetricBits(p.l+nHatBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample m")
	}
	delta, err := intSampleRangeSymmetricBits(p.lPrime+p.epsilon+nHatBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample delta")
	}
	mu, err := intSampleRangeSymmetricBits(p.lPrime+nHatBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample mu")
	}
	r, err := statement.n0.SampleNonce(p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample r")
	}
	ry, err := statement.n1.SampleNonce(p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample ry")
	}

	state, err := NewState(alpha, beta, gamma, m, delta, mu, r, ry)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create state")
	}
	return state, nil
}

func (p *Protocol[G, B, S]) computeCommitment(statement *Statement[G, B, S], witness *Witness, state *State) (*Commitment[G, B, S], error) {
	betaN0, err := intToPlaintext(state.beta, statement.n0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create beta plaintext for N0")
	}
	encBetaN0, err := statement.n0.EncryptWithNonce(betaN0, state.r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt beta under N0")
	}
	cAlpha, err := statement.n0.CiphertextScalarOp(statement.c, state.alpha)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute C^alpha")
	}
	a, err := statement.n0.CiphertextOp(cAlpha, encBetaN0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute A")
	}

	alphaScalar, err := intToScalar(state.alpha, p.curve.ScalarField())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert alpha to scalar")
	}
	bx := p.curve.ScalarBaseMul(alphaScalar)

	betaN1, err := intToPlaintext(state.beta, statement.n1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create beta plaintext for N1")
	}
	by, err := statement.n1.EncryptWithNonce(betaN1, state.ry)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute By")
	}

	y := witness.y.Normalise()
	s, err := p.commit(witness.x, state.m)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute S")
	}
	t, err := p.commit(y, state.mu)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute T")
	}
	e, err := p.commit(state.alpha, state.gamma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute E")
	}
	f, err := p.commit(state.beta, state.delta)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute F")
	}

	commitment, err := NewCommitment(a, bx, by, e, f, s, t)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	return commitment, nil
}

func (*Protocol[G, B, S]) simulateA(statement *Statement[G, B, S], response *Response, e *num.Int) (*paillier.Ciphertext, error) {
	cZ1, err := statement.n0.CiphertextScalarOp(statement.c, response.z1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute C^z1")
	}
	z2N0, err := intToPlaintext(response.z2, statement.n0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create z2 plaintext for N0")
	}
	encZ2, err := statement.n0.EncryptWithNonce(z2N0, response.w)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt z2")
	}
	left, err := statement.n0.CiphertextOp(cZ1, encZ2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute response side")
	}
	dNegE, err := statement.n0.CiphertextScalarOp(statement.d, e.Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute D^-e")
	}
	a, err := statement.n0.CiphertextOp(left, dNegE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute A")
	}
	return a, nil
}

func (p *Protocol[G, B, S]) simulateBX(statement *Statement[G, B, S], response *Response, e *num.Int) (G, error) {
	z1Scalar, err := intToScalar(response.z1, p.curve.ScalarField())
	if err != nil {
		return *new(G), errs.Wrap(err).WithMessage("could not convert z1 to scalar")
	}
	eNegScalar, err := intToScalar(e.Neg(), p.curve.ScalarField())
	if err != nil {
		return *new(G), errs.Wrap(err).WithMessage("could not convert challenge to scalar")
	}
	return p.curve.ScalarBaseMul(z1Scalar).Op(statement.x.ScalarOp(eNegScalar)), nil
}

func (*Protocol[G, B, S]) simulateBY(statement *Statement[G, B, S], response *Response, e *num.Int) (*paillier.Ciphertext, error) {
	z2N1, err := intToPlaintext(response.z2, statement.n1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create z2 plaintext for N1")
	}
	left, err := statement.n1.EncryptWithNonce(z2N1, response.wy)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt z2")
	}
	yNegE, err := statement.n1.CiphertextScalarOp(statement.y, e.Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute Y^-e")
	}
	by, err := statement.n1.CiphertextOp(left, yNegE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute By")
	}
	return by, nil
}

func (p *Protocol[G, B, S]) simulatePedersen(message, witness *num.Int, baseCommitment *intcom.Commitment, e *num.Int) (*intcom.Commitment, error) {
	left, err := p.commit(message, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute response commitment")
	}
	baseNegE, err := p.ringPedersenKey.CommitmentScalarOp(baseCommitment, e.Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not exponentiate base commitment")
	}
	out, err := p.ringPedersenKey.CommitmentOp(left, baseNegE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute simulated commitment")
	}
	return out, nil
}

func (p *Protocol[G, B, S]) commit(messageValue, witnessValue *num.Int) (*intcom.Commitment, error) {
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

func (*Protocol[G, B, S]) mapChallenge(challenge sigma.ChallengeBytes) (*num.Int, error) {
	if len(challenge) != base.ComputationalSecurityBytesCeil {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	out, err := num.Z().FromTwosComplementBytesBE(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not parse challenge")
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
	if !statement.n0.CiphertextGroup().Contains(commitment.a.Value()) {
		return ErrValidationFailed.WithMessage("A must be in the N0 ciphertext group")
	}
	if !statement.n1.CiphertextGroup().Contains(commitment.by.Value()) {
		return ErrValidationFailed.WithMessage("By must be in the N1 ciphertext group")
	}
	if !p.curve.Contains(commitment.bx) {
		return ErrValidationFailed.WithMessage("Bx must be in the curve group")
	}
	group := p.ringPedersenKey.CommitmentGroup()
	for _, elem := range []*intcom.Commitment{commitment.e, commitment.f, commitment.s, commitment.t} {
		if !group.Contains(elem.Value()) {
			return ErrValidationFailed.WithMessage("Pedersen commitment must be in the commitment group")
		}
	}
	return nil
}

func (*Protocol[G, B, S]) validateResponse(statement *Statement[G, B, S], response *Response) error {
	if !statement.n0.NonceGroup().Contains(response.w.Value()) {
		return ErrValidationFailed.WithMessage("w must be in the N0 nonce group")
	}
	if !statement.n1.NonceGroup().Contains(response.wy.Value()) {
		return ErrValidationFailed.WithMessage("wy must be in the N1 nonce group")
	}
	return nil
}
