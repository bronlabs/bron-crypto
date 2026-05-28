package enc

import (
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Protocol implements CGGMP21 Figure 11, Paillier Encryption in Range ZK.
type Protocol[EK paillier.EncryptionKey[EK]] struct {
	name sigma.Name

	paillierKey     EK
	ringPedersenKey *intcom.CommitmentKey
	rangeBits       int
	slackBits       int
	prng            io.Reader
}

// NewProtocol constructs the CGGMP21 Paillier encryption-in-range sigma protocol.
// ValidateStatement enforces the honest-prover witness range
// [-2^rangeBits, 2^rangeBits), with the lower endpoint conservatively
// rejected. Verification proves only the widened range
// [-2^(rangeBits+slackBits), 2^(rangeBits+slackBits)).
func NewProtocol[EK paillier.EncryptionKey[EK]](
	paillierKey EK,
	ringPedersenKey *intcom.CommitmentKey,
	rangeBits int,
	slackBits int,
	prng io.Reader,
) (*Protocol[EK], error) {
	if utils.IsNil(paillierKey) {
		return nil, ErrInvalidArgument.WithMessage("paillierKey must not be nil")
	}
	if ringPedersenKey == nil {
		return nil, ErrInvalidArgument.WithMessage("ringPedersenKey must not be nil")
	}
	if paillierKey.PlaintextGroup().Modulus().TrueLen()%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("Paillier modulus bit length must be a multiple of 8")
	}
	if ringPedersenKey.Group().Modulus().TrueLen()%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("Ring-Pedersen modulus bit length must be a multiple of 8")
	}
	if rangeBits%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("rangeBits must be a multiple of 8")
	}
	if slackBits%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("slackBits must be a multiple of 8")
	}
	if rangeBits < base.ComputationalSecurityBits || rangeBits >= min(paillierKey.PlaintextGroup().Modulus().TrueLen(), ringPedersenKey.Group().Modulus().TrueLen()) {
		return nil, ErrInvalidArgument.WithMessage("rangeBits out of range")
	}
	if slackBits < challengeBitsLength+base.ComputationalSecurityBits || slackBits >= min(paillierKey.PlaintextGroup().Modulus().TrueLen(), ringPedersenKey.Group().Modulus().TrueLen()) {
		return nil, ErrInvalidArgument.WithMessage("slackBits out of range")
	}
	if slackBits < rangeBits+base.ComputationalSecurityBits {
		return nil, ErrInvalidArgument.WithMessage("invalid slackBits")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng must not be nil")
	}
	if err := signedBoundFitsPaillier(rangeBits+slackBits, paillierKey); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid Paillier modulus for configured range")
	}

	name := sigma.Name(fmt.Sprintf(
		"%s_L=%d_EPS=%d_N=%s_NHAT=%s_S=%x_T=%x",
		Name,
		rangeBits,
		slackBits,
		paillierKey.PlaintextGroup().Modulus().String(),
		ringPedersenKey.Group().Modulus().String(),
		ringPedersenKey.S().Bytes(),
		ringPedersenKey.T().Bytes(),
	))
	return &Protocol[EK]{
		name:            name,
		paillierKey:     paillierKey,
		ringPedersenKey: ringPedersenKey,
		rangeBits:       rangeBits,
		slackBits:       slackBits,
		prng:            prng,
	}, nil
}

// Name returns the protocol identifier, including public parameters.
func (p *Protocol[EK]) Name() sigma.Name {
	return p.name
}

// ComputeProverCommitment generates the prover's first message.
func (p *Protocol[EK]) ComputeProverCommitment(statement *Statement, witness *Witness) (*Commitment, *State, error) {
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement or witness")
	}

	kMessage, err := intcom.NewMessage(witness.k.Normalise())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create k commitment message")
	}
	alpha, err := intRandomBitsSymmetric(p.rangeBits+p.slackBits, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample alpha")
	}
	alphaPlaintext, err := intToPlaintext(alpha, p.paillierKey)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create alpha plaintext")
	}
	alphaMessage, err := intcom.NewMessage(alpha)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create alpha commitment message")
	}
	muInt, err := intRandomBitsSymmetric(p.rangeBits+p.ringPedersenKey.Group().Modulus().TrueLen(), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample mu")
	}
	mu, err := intcom.NewWitness(muInt)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create mu commitment witness")
	}
	gammaInt, err := intRandomBitsSymmetric(p.rangeBits+p.slackBits+p.ringPedersenKey.Group().Modulus().TrueLen(), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample gamma")
	}
	gamma, err := intcom.NewWitness(gammaInt)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create gamma commitment witness")
	}
	r, err := p.paillierKey.SampleNonce(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample r")
	}

	s, err := p.ringPedersenKey.CommitWithWitness(kMessage, mu)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute S")
	}
	a, err := p.paillierKey.EncryptWithNonce(alphaPlaintext, r)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute A")
	}
	c, err := p.ringPedersenKey.CommitWithWitness(alphaMessage, gamma)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute C")
	}

	commitment, err := NewCommitment(s, a, c)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	state, err := NewState(alphaPlaintext, mu, r, gamma)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create state")
	}
	return commitment, state, nil
}

// ComputeProverResponse computes z1 = alpha + e*k, z2 = r*rho^e, and z3 = gamma + e*mu.
func (p *Protocol[EK]) ComputeProverResponse(
	statement *Statement,
	witness *Witness,
	_ *Commitment,
	state *State,
	challenge sigma.ChallengeBytes,
) (*Response, error) {
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid statement or witness")
	}
	eInt, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	z1 := state.alpha.Normalise().Add(eInt.Mul(witness.k.Normalise()))
	z1Plaintext, err := intToPlaintext(z1, p.paillierKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create z1 plaintext")
	}
	rhoE, err := p.paillierKey.NonceScalarOp(witness.rho, eInt)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute rho^e")
	}
	z2, err := p.paillierKey.NonceOp(state.r, rhoE)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute z2")
	}
	z3, err := intcom.NewWitness(state.gamma.Value().Add(eInt.Mul(state.mu.Value())))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create z3")
	}

	response, err := NewResponse(z1Plaintext, z2, z3)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return response, nil
}

// Verify checks the two Figure 11 equality checks and the widened response range.
func (p *Protocol[EK]) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid challenge")
	}
	if !p.paillierKey.CiphertextGroup().Contains(statement.k.Value()) {
		return ErrVerificationFailed.WithMessage("K is not in the ciphertext group")
	}
	if !p.paillierKey.CiphertextGroup().Contains(commitment.a.Value()) {
		return ErrVerificationFailed.WithMessage("A is not in the ciphertext group")
	}
	if !p.paillierKey.PlaintextGroup().Contains(response.z1.Value()) {
		return ErrVerificationFailed.WithMessage("z1 is not in the plaintext group")
	}
	if !p.paillierKey.NonceGroup().Contains(response.z2.Value()) {
		return ErrVerificationFailed.WithMessage("z2 is not in the nonce group")
	}
	if !p.ringPedersenKey.CommitmentGroup().Contains(commitment.s.Value()) ||
		!p.ringPedersenKey.CommitmentGroup().Contains(commitment.c.Value()) {

		return ErrVerificationFailed.WithMessage("Pedersen commitments are not in the commitment group")
	}

	z1 := response.z1.Normalise()
	if !inSignedBitRange(z1, p.rangeBits+p.slackBits) {
		return ErrVerificationFailed.WithMessage("z1 is out of range")
	}
	leftCiphertext, err := p.paillierKey.EncryptWithNonce(response.z1, response.z2)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Paillier equality left side")
	}
	ke, err := p.paillierKey.CiphertextScalarOp(statement.k, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute K^e")
	}
	rightCiphertext, err := p.paillierKey.CiphertextOp(commitment.a, ke)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Paillier equality right side")
	}
	if !leftCiphertext.Equal(rightCiphertext) {
		return ErrVerificationFailed.WithMessage("Paillier equality check failed")
	}

	z1Message, err := intcom.NewMessage(z1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create z1 commitment message")
	}
	leftCommitment, err := p.ringPedersenKey.CommitWithWitness(z1Message, response.z3)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Pedersen equality left side")
	}
	se, err := p.ringPedersenKey.CommitmentScalarOp(commitment.s, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute S^e")
	}
	rightCommitment, err := p.ringPedersenKey.CommitmentOp(commitment.c, se)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Pedersen equality right side")
	}
	if !leftCommitment.Equal(rightCommitment) {
		return ErrVerificationFailed.WithMessage("Pedersen equality check failed")
	}

	return nil
}

// RunSimulator creates a simulated accepting transcript for the supplied challenge.
func (p *Protocol[EK]) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid challenge")
	}
	if !p.paillierKey.CiphertextGroup().Contains(statement.k.Value()) {
		return nil, nil, ErrInvalidArgument.WithMessage("K is not in the ciphertext group")
	}

	z1, err := intRandomBitsSymmetric(p.rangeBits+p.slackBits, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z1")
	}
	z1Plaintext, err := intToPlaintext(z1, p.paillierKey)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create z1 plaintext")
	}
	z2, err := p.paillierKey.SampleNonce(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z2")
	}
	z3, err := intRandomBitsSymmetric(p.rangeBits+p.slackBits+p.ringPedersenKey.Group().Modulus().TrueLen(), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z3")
	}
	z3Witness, err := intcom.NewWitness(z3)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create z3 witness")
	}

	lambda, err := intRandomBitsSymmetric(p.rangeBits+p.ringPedersenKey.Group().Modulus().TrueLen(), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample lambda")
	}
	zeroMessage, err := intcom.NewMessage(num.Z().Zero())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create zero message")
	}
	lambdaWitness, err := intcom.NewWitness(lambda)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create lambda witness")
	}
	s, err := p.ringPedersenKey.CommitWithWitness(zeroMessage, lambdaWitness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute S")
	}

	encryptedZ1, err := p.paillierKey.EncryptWithNonce(z1Plaintext, z2)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not encrypt z1")
	}
	kNegE, err := p.paillierKey.CiphertextScalarOp(statement.k, e.Neg())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute K^-e")
	}
	a, err := p.paillierKey.CiphertextOp(encryptedZ1, kNegE)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute A")
	}

	z1Message, err := intcom.NewMessage(z1)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create z1 message")
	}
	committedZ1, err := p.ringPedersenKey.CommitWithWitness(z1Message, z3Witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not commit to z1")
	}
	sNegE, err := p.ringPedersenKey.CommitmentScalarOp(s, e.Neg())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute S^-e")
	}
	c, err := p.ringPedersenKey.CommitmentOp(committedZ1, sNegE)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute C")
	}

	commitment, err := NewCommitment(s, a, c)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	response, err := NewResponse(z1Plaintext, z2, z3Witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return commitment, response, nil
}

// SpecialSoundness returns the protocol special soundness parameter.
func (*Protocol[EK]) SpecialSoundness() uint {
	return specialSoundness
}

// SoundnessError returns the 128-bit challenge size used as the soundness error.
func (*Protocol[EK]) SoundnessError() uint {
	return uint(challengeBitsLength)
}

// GetChallengeBytesLength returns the byte length used to encode challenges.
func (*Protocol[EK]) GetChallengeBytesLength() int {
	return challengeBytesLength
}

// ValidateStatement checks that witness opens the statement and lies in the configured range.
func (p *Protocol[EK]) ValidateStatement(statement *Statement, witness *Witness) error {
	if !p.paillierKey.CiphertextGroup().Contains(statement.k.Value()) {
		return ErrValidationFailed.WithMessage("K is not in the ciphertext group")
	}
	if !p.paillierKey.PlaintextGroup().Contains(witness.k.Value()) {
		return ErrValidationFailed.WithMessage("k is not in the plaintext group")
	}
	if !p.paillierKey.NonceGroup().Contains(witness.rho.Value()) {
		return ErrValidationFailed.WithMessage("rho is not in the nonce group")
	}
	if !inSignedBitRange(witness.k.Normalise(), p.rangeBits) {
		return ErrValidationFailed.WithMessage("k is out of range")
	}
	kCheck, err := p.paillierKey.EncryptWithNonce(witness.k, witness.rho)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not recompute K")
	}
	if !statement.k.Equal(kCheck) {
		return ErrValidationFailed.WithMessage("witness does not open K")
	}
	return nil
}

func (p *Protocol[EK]) mapChallenge(challenge sigma.ChallengeBytes) (*num.Int, error) {
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	e, err := num.Z().FromTwosComplementBytesBE(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not parse challenge")
	}
	return e, nil
}
