package encelg

import (
	"fmt"
	"io"
	"testing"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Protocol implements the CGGMP21 range proof with ElGamal commitment from Figure 24.
type Protocol[
	G curves.Point[G, B, S],
	B algebra.PrimeFieldElement[B],
	S algebra.PrimeFieldElement[S],
] struct {
	name                 sigma.Name
	ringPedersenKey      *intcom.CommitmentKey
	elgamalCommitmentKey *indcpacom.HomomorphicCommitmentKey[*elgamal.PublicKey[G, S], *elgamal.Plaintext[G, S], *elgamal.Nonce[S], *elgamal.Ciphertext[G, S], S]
	l                    int
	epsilon              int
	scalarField          algebra.PrimeField[S]
	prng                 io.Reader
}

// NewProtocol constructs the CGGMP21 Figure 24 range proof with ElGamal commitment.
func NewProtocol[
	G curves.Point[G, B, S],
	B algebra.PrimeFieldElement[B],
	S algebra.PrimeFieldElement[S],
](
	ringPedersenKey *intcom.CommitmentKey,
	elgamalCommitmentKey *indcpacom.HomomorphicCommitmentKey[*elgamal.PublicKey[G, S], *elgamal.Plaintext[G, S], *elgamal.Nonce[S], *elgamal.Ciphertext[G, S], S],
	l, epsilon int,
	prng io.Reader,
) (*Protocol[G, B, S], error) {
	if ringPedersenKey == nil || ringPedersenKey.Group().Modulus().TrueLen()%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("ringPedersenKey is required")
	}
	if elgamalCommitmentKey == nil {
		return nil, ErrInvalidArgument.WithMessage("elgamalCommitmentKey is required")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng is required")
	}
	if (l <= 0) || (l%8 != 0) {
		return nil, ErrInvalidArgument.WithMessage("l must be a multiple of 8")
	}
	if (epsilon <= 0) || (epsilon%8 != 0) {
		return nil, ErrInvalidArgument.WithMessage("epsilon must be a multiple of 8")
	}

	scalarField, err := algebra.StructureAs[algebra.PrimeField[S]](elgamalCommitmentKey.EncryptionKey().NonceGroup())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid ElGamal scalar field")
	}
	k := scalarField.BitLen()
	if k < base.ComputationalSecurityBits {
		return nil, ErrInvalidArgument.WithMessage("invalid curve")
	}
	if l < k {
		return nil, ErrInvalidArgument.WithMessage("invalid l")
	}
	if epsilon < l+k {
		return nil, ErrInvalidArgument.WithMessage("invalid epsilon")
	}
	logN := ringPedersenKey.Group().Modulus().TrueLen()
	if logN < l+epsilon {
		return nil, ErrInvalidArgument.WithMessage("invalid ring pedersen key")
	}
	if !testing.Testing() && logN < base.IFCKeyLength {
		return nil, ErrInvalidArgument.WithMessage("invalid ring pedersen key len")
	}
	elgamalCommitmentKeyBytes, err := elgamalCommitmentKey.MarshalCBOR()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal ElGamal commitment key")
	}

	name := sigma.Name(fmt.Sprintf(
		"%s_L=%d_EPS=%d_GROUP=%s_NHAT=%s_S=%x_T=%x_ELGAMAL=%x",
		Name,
		l,
		epsilon,
		elgamalCommitmentKey.EncryptionKey().PlaintextGroup().Name(),
		ringPedersenKey.Group().Modulus().String(),
		ringPedersenKey.S().Bytes(),
		ringPedersenKey.T().Bytes(),
		elgamalCommitmentKeyBytes,
	))
	p := &Protocol[G, B, S]{
		name:                 name,
		ringPedersenKey:      ringPedersenKey,
		elgamalCommitmentKey: elgamalCommitmentKey,
		l:                    l,
		epsilon:              epsilon,
		scalarField:          scalarField,
		prng:                 prng,
	}
	return p, nil
}

// Name returns the protocol identifier, including public parameters.
func (p *Protocol[G, B, S]) Name() sigma.Name {
	return p.name
}

// ComputeProverCommitment generates the prover's first message.
func (p *Protocol[G, B, S]) ComputeProverCommitment(statement *Statement[G, B, S], witness *Witness[S]) (*Commitment[G, B, S], *State[S], error) {
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
func (p *Protocol[G, B, S]) ComputeProverResponse(statement *Statement[G, B, S], witness *Witness[S], commitment *Commitment[G, B, S], state *State[S], challenge sigma.ChallengeBytes) (*Response[S], error) {
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
	e, eScalar, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	z1 := state.alpha.Add(e.Mul(witness.x))
	rhoE, err := statement.n0.NonceScalarOp(witness.rho, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute rho^e")
	}
	z2, err := statement.n0.NonceOp(state.r, rhoE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute z2")
	}
	z3 := state.gamma.Add(e.Mul(state.mu))
	w := state.beta.Add(eScalar.Mul(witness.bx.Value().Value()))

	response, err := NewResponse(z1, z2, z3, w)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return response, nil
}

// Verify checks the Figure 24 equality checks and widened response range.
func (p *Protocol[G, B, S]) Verify(statement *Statement[G, B, S], commitment *Commitment[G, B, S], challenge sigma.ChallengeBytes, response *Response[S]) error {
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
	e, eScalar, err := p.mapChallenge(challenge)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid challenge")
	}

	if !intInSignedBitRange(response.z1, p.l+p.epsilon) {
		return ErrVerificationFailed.WithMessage("z1 is out of range")
	}
	if err := p.verifyPaillier(statement, commitment, response, e); err != nil {
		return errs.Wrap(err).WithMessage("Paillier equality failed")
	}
	if err := p.verifyElGamal(statement, commitment, response, eScalar); err != nil {
		return errs.Wrap(err).WithMessage("ElGamal equality failed")
	}
	if err := p.verifyPedersen(commitment, response, e); err != nil {
		return errs.Wrap(err).WithMessage("Pedersen equality failed")
	}
	return nil
}

// RunSimulator creates an honest-verifier simulated transcript for a fixed challenge.
func (p *Protocol[G, B, S]) RunSimulator(statement *Statement[G, B, S], challenge sigma.ChallengeBytes) (*Commitment[G, B, S], *Response[S], error) {
	if statement == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if err := p.validateStatement(statement); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	e, eScalar, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	z1, err := intSampleRangeSymmetricBits(p.l+p.epsilon, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z1")
	}
	z2, err := statement.n0.SampleNonce(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z2")
	}
	z3, err := intSampleRangeSymmetricBits(p.l+p.epsilon+p.ringPedersenKey.Group().Modulus().TrueLen(), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z3")
	}
	w, err := p.scalarField.Random(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample w")
	}
	response, err := NewResponse(z1, z2, z3, w)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create response")
	}

	lambda, err := intSampleRangeSymmetricBits(p.l+p.ringPedersenKey.Group().Modulus().TrueLen(), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample S opening")
	}
	sCommitment, err := p.commit(num.Z().Zero(), lambda)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated S")
	}
	d, err := p.simulateD(statement, response, e)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated D")
	}
	yz, err := p.simulateElGamal(statement, response, eScalar)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated ElGamal commitment")
	}
	t, err := p.simulateT(sCommitment, response, e)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated T")
	}

	commitment, err := NewCommitment(sCommitment, t, d, yz)
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

// ValidateStatement checks that the witness opens the public statement and lies in the configured range.
func (p *Protocol[G, B, S]) ValidateStatement(statement *Statement[G, B, S], witness *Witness[S]) error {
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

func (p *Protocol[G, B, S]) sampleState(statement *Statement[G, B, S]) (*State[S], error) {
	nHatBitLen := p.ringPedersenKey.Group().Modulus().TrueLen()

	alpha, err := intSampleRangeSymmetricBits(p.l+p.epsilon, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample alpha")
	}
	beta, err := p.scalarField.Random(p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample beta")
	}
	mu, err := intSampleRangeSymmetricBits(p.l+nHatBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample mu")
	}
	r, err := statement.n0.SampleNonce(p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample r")
	}
	gamma, err := intSampleRangeSymmetricBits(p.l+p.epsilon+nHatBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample gamma")
	}

	state, err := NewState(alpha, beta, mu, r, gamma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create state")
	}
	return state, nil
}

func (p *Protocol[G, B, S]) computeCommitment(statement *Statement[G, B, S], witness *Witness[S], state *State[S]) (*Commitment[G, B, S], error) {
	sCommitment, err := p.commit(witness.x, state.mu)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute S")
	}
	dPlaintext, err := intToPlaintext(state.alpha, statement.n0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create alpha plaintext")
	}
	d, err := statement.n0.EncryptWithNonce(dPlaintext, state.r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute D")
	}
	yz, err := p.commitElGamal(state.alpha, state.beta)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute YZ")
	}
	t, err := p.commit(state.alpha, state.gamma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute T")
	}

	commitment, err := NewCommitment(sCommitment, t, d, yz)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	return commitment, nil
}

func (*Protocol[G, B, S]) verifyPaillier(statement *Statement[G, B, S], commitment *Commitment[G, B, S], response *Response[S], e *num.Int) error {
	z1Plaintext, err := intToPlaintext(response.z1, statement.n0)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create z1 plaintext")
	}
	left, err := statement.n0.EncryptWithNonce(z1Plaintext, response.z2)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Paillier left side")
	}
	cE, err := statement.n0.CiphertextScalarOp(statement.c, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute C^e")
	}
	right, err := statement.n0.CiphertextOp(commitment.d, cE)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Paillier right side")
	}
	if !left.Equal(right) {
		return ErrVerificationFailed.WithMessage("Paillier equality check failed")
	}
	return nil
}

func (p *Protocol[G, B, S]) commitElGamal(message *num.Int, nonceValue S) (*indcpacom.Commitment[*elgamal.Ciphertext[G, S]], error) {
	messageScalar, err := intToScalar(message, p.scalarField)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert message to scalar")
	}
	plaintext, err := elgamal.NewPlaintext[G, S](p.elgamalCommitmentKey.EncryptionKey().PlaintextGroup().Generator().ScalarOp(messageScalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ElGamal plaintext")
	}
	commitmentMessage, err := indcpacom.NewMessage(plaintext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ElGamal commitment message")
	}
	nonce, err := elgamal.NewNonce[S](nonceValue)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ElGamal nonce")
	}
	witness, err := indcpacom.NewWitness(nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ElGamal commitment witness")
	}
	out, err := p.elgamalCommitmentKey.CommitWithWitness(commitmentMessage, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute ElGamal commitment")
	}
	return out, nil
}

func (p *Protocol[G, B, S]) verifyElGamal(statement *Statement[G, B, S], commitment *Commitment[G, B, S], response *Response[S], e S) error {
	left, err := p.commitElGamal(response.z1, response.w)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute ElGamal left side")
	}
	bxE, err := p.elgamalCommitmentKey.CommitmentScalarOp(statement.bx, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute BX^e")
	}
	right, err := p.elgamalCommitmentKey.CommitmentOp(commitment.yz, bxE)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute ElGamal right side")
	}
	if !left.Equal(right) {
		return ErrVerificationFailed.WithMessage("ElGamal equality check failed")
	}
	return nil
}

func (p *Protocol[G, B, S]) verifyPedersen(commitment *Commitment[G, B, S], response *Response[S], e *num.Int) error {
	left, err := p.commit(response.z1, response.z3)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Pedersen left side")
	}
	sE, err := p.ringPedersenKey.CommitmentScalarOp(commitment.s, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute S^e")
	}
	right, err := p.ringPedersenKey.CommitmentOp(commitment.t, sE)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Pedersen right side")
	}
	if !left.Equal(right) {
		return ErrVerificationFailed.WithMessage("Pedersen equality check failed")
	}
	return nil
}

func (*Protocol[G, B, S]) simulateD(statement *Statement[G, B, S], response *Response[S], e *num.Int) (*paillier.Ciphertext, error) {
	z1Plaintext, err := intToPlaintext(response.z1, statement.n0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create z1 plaintext")
	}
	encryptedZ1, err := statement.n0.EncryptWithNonce(z1Plaintext, response.z2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt z1")
	}
	cNegE, err := statement.n0.CiphertextScalarOp(statement.c, e.Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute C^-e")
	}
	out, err := statement.n0.CiphertextOp(encryptedZ1, cNegE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute D")
	}
	return out, nil
}

func (p *Protocol[G, B, S]) simulateElGamal(statement *Statement[G, B, S], response *Response[S], e S) (*indcpacom.Commitment[*elgamal.Ciphertext[G, S]], error) {
	left, err := p.commitElGamal(response.z1, response.w)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute ElGamal left side")
	}
	bxE, err := p.elgamalCommitmentKey.CommitmentScalarOp(statement.bx, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute BX^e")
	}
	bxNegE, err := p.elgamalCommitmentKey.CommitmentOpInv(bxE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute BX^-e")
	}
	out, err := p.elgamalCommitmentKey.CommitmentOp(left, bxNegE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute simulated ElGamal commitment")
	}
	return out, nil
}

func (p *Protocol[G, B, S]) simulateT(sCommitment *intcom.Commitment, response *Response[S], e *num.Int) (*intcom.Commitment, error) {
	left, err := p.commit(response.z1, response.z3)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute response commitment")
	}
	sNegE, err := p.ringPedersenKey.CommitmentScalarOp(sCommitment, e.Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute S^-e")
	}
	out, err := p.ringPedersenKey.CommitmentOp(left, sNegE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute T")
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

func (p *Protocol[G, B, S]) mapChallenge(challenge sigma.ChallengeBytes) (*num.Int, S, error) {
	var nilS S
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, nilS, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	e, err := num.Z().FromTwosComplementBytesBE(challenge)
	if err != nil {
		return nil, nilS, errs.Wrap(err).WithMessage("could not parse challenge")
	}
	eScalar, err := intToScalar(e, p.scalarField)
	if err != nil {
		return nil, nilS, errs.Wrap(err).WithMessage("could not convert challenge to scalar")
	}
	return e, eScalar, nil
}

func (p *Protocol[G, B, S]) validateStatement(statement *Statement[G, B, S]) error {
	if statement.n0.PlaintextGroup().Modulus().TrueLen()%8 != 0 {
		return ErrValidationFailed.WithMessage("Paillier modulus bit length must be byte-aligned")
	}
	if err := signedBoundFitsPaillier(p.l+p.epsilon, statement.n0); err != nil {
		return errs.Wrap(err).WithMessage("invalid N0 modulus for z1 response range")
	}
	if !statement.n0.CiphertextGroup().Contains(statement.c.Value()) {
		return ErrValidationFailed.WithMessage("C must be in the N0 ciphertext group")
	}
	if !p.elgamalCommitmentKey.EncryptionKey().CiphertextGroup().Contains(statement.bx.Value().Value()) {
		return ErrValidationFailed.WithMessage("BX must be in the ElGamal ciphertext group")
	}
	return nil
}

func (p *Protocol[G, B, S]) validateWitness(statement *Statement[G, B, S], witness *Witness[S]) error {
	if !intInSignedBitRange(witness.x, p.l) {
		return ErrValidationFailed.WithMessage("x is out of range")
	}
	if !statement.n0.NonceGroup().Contains(witness.rho.Value()) {
		return ErrValidationFailed.WithMessage("rho is not in the N0 nonce group")
	}

	xPlaintext, err := intToPlaintext(witness.x, statement.n0)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create x plaintext")
	}
	cCheck, err := statement.n0.EncryptWithNonce(xPlaintext, witness.rho)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not recompute C")
	}
	if !statement.c.Equal(cCheck) {
		return ErrValidationFailed.WithMessage("witness does not open C")
	}
	xScalar, err := intToScalar(witness.x, p.scalarField)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not convert x to scalar")
	}
	elgamalPlaintext, err := elgamal.NewPlaintext[G, S](p.elgamalCommitmentKey.EncryptionKey().PlaintextGroup().Generator().ScalarOp(xScalar))
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create ElGamal plaintext")
	}
	elgamalMessage, err := indcpacom.NewMessage(elgamalPlaintext)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create ElGamal commitment message")
	}
	if err := p.elgamalCommitmentKey.Open(statement.bx, elgamalMessage, witness.bx); err != nil {
		return errs.Wrap(err).WithMessage("witness does not open BX")
	}
	return nil
}

func (p *Protocol[G, B, S]) validateCommitment(statement *Statement[G, B, S], commitment *Commitment[G, B, S]) error {
	group := p.ringPedersenKey.CommitmentGroup()
	if !group.Contains(commitment.s.Value()) || !group.Contains(commitment.t.Value()) {
		return ErrValidationFailed.WithMessage("Pedersen commitments must be in the commitment group")
	}
	if !statement.n0.CiphertextGroup().Contains(commitment.d.Value()) {
		return ErrValidationFailed.WithMessage("D must be in the N0 ciphertext group")
	}
	if !p.elgamalCommitmentKey.EncryptionKey().CiphertextGroup().Contains(commitment.yz.Value().Value()) {
		return ErrValidationFailed.WithMessage("YZ must be in the ElGamal ciphertext group")
	}
	return nil
}

func (*Protocol[G, B, S]) validateResponse(statement *Statement[G, B, S], response *Response[S]) error {
	if !statement.n0.NonceGroup().Contains(response.z2.Value()) {
		return ErrValidationFailed.WithMessage("z2 must be in the N0 nonce group")
	}
	return nil
}
