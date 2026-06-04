package prm

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Protocol implements the CGGMP21 Pedersen parameters proof.
type Protocol struct {
	prng io.Reader
}

// NewProtocol constructs a CGGMP21 Pedersen parameters proof instance.
func NewProtocol(prng io.Reader) (*Protocol, error) {
	if prng == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("prng must not be nil")
	}
	return &Protocol{prng: prng}, nil
}

// Name returns the protocol identifier.
func (*Protocol) Name() sigma.Name {
	return Name
}

// ComputeProverCommitment generates the first prover message.
func (p *Protocol) ComputeProverCommitment(statement *Statement, witness *Witness) (*Commitment, *State, error) {
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement or witness")
	}

	t, err := witness.trapdoorKey.T().LearnOrder(witness.trapdoorKey.Group())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not learn t order")
	}
	phi, err := phiFromGroup(witness.trapdoorKey.Group())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute phi(N)")
	}
	zPhi, err := num.NewZMod(phi)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create Z/phi(N)Z")
	}

	var a [m]*znstar.RSAGroupElementUnknownOrder
	var alphas [m]*num.Uint
	for i := range &a {
		alpha, err := zPhi.Random(p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample alpha")
		}
		a[i] = t.Exp(alpha.Nat()).ForgetOrder()
		alphas[i] = alpha
	}
	commitment, err := NewCommitment(a[:]...)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	state, err := NewState(alphas[:]...)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create state")
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
	if err := validateCommitment(statement, commitment); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid commitment")
	}
	if state == nil {
		return nil, ErrInvalidArgument.WithMessage("state must not be nil")
	}
	if len(challenge) != challengeBytes {
		return nil, proofs.ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	t, err := witness.trapdoorKey.T().LearnOrder(witness.trapdoorKey.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn t order")
	}
	phi, err := phiFromGroup(witness.trapdoorKey.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute phi(N)")
	}
	lambda := witness.trapdoorKey.Lambda().Lift().Mod(phi)

	var z [m]*num.Int
	for i := range &z {
		alpha := state.alpha[i]
		if !alpha.Modulus().Equal(phi) {
			return nil, proofs.ErrValidationFailed.WithMessage("state alpha has wrong modulus")
		}
		expected := t.Exp(alpha.Nat()).ForgetOrder()
		if !expected.Equal(commitment.a[i]) {
			return nil, proofs.ErrValidationFailed.WithMessage("commitment and state mismatch")
		}

		if challengeBit(challenge, i) != 0 {
			z[i] = alpha.Add(lambda).Lift()
		} else {
			z[i] = alpha.Lift()
		}
	}
	response, err := NewResponse(z[:]...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return response, nil
}

// Verify checks a prover response against the statement and commitment.
func (*Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	if response == nil {
		return ErrInvalidArgument.WithMessage("response must not be nil")
	}
	if err := validateCommitment(statement, commitment); err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment")
	}
	if len(challenge) != challengeBytes {
		return proofs.ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	s := statement.commitmentKey.S()
	t := statement.commitmentKey.T()
	n := statement.commitmentKey.Group().Modulus().Nat()
	for i, z := range &response.z {
		// Honest responses satisfy z < phi(N) < N, and simulator responses are
		// sampled below N; reject huge parsed exponents before modular exponentiation.
		if !z.Abs().IsLessThanOrEqual(n) {
			return proofs.ErrVerificationFailed.WithMessage("response z is out of range")
		}

		lhs := t.ExpI(z)
		rhs := commitment.a[i]
		if challengeBit(challenge, i) == 1 {
			rhs = rhs.Mul(s)
		}
		if !lhs.Equal(rhs) {
			return proofs.ErrVerificationFailed.WithMessage("response does not satisfy verification equation")
		}
	}
	return nil
}

// RunSimulator creates an honest-verifier simulated transcript for a fixed challenge.
func (p *Protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	if statement == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if len(challenge) != challengeBytes {
		return nil, nil, proofs.ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	sInv, err := statement.commitmentKey.S().TryInv()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not invert s")
	}
	t := statement.commitmentKey.T()
	n := statement.commitmentKey.Group().Modulus()
	low := num.Z().Zero()
	high := n.Lift()

	var a [m]*znstar.RSAGroupElementUnknownOrder
	var zs [m]*num.Int
	for i := range &a {
		z, err := num.Z().Random(low, high, p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample simulator response")
		}
		commitmentElement := t.ExpI(z)
		if challengeBit(challenge, i) == 1 {
			commitmentElement = commitmentElement.Mul(sInv)
		}

		a[i] = commitmentElement
		zs[i] = z
	}
	commitment, err := NewCommitment(a[:]...)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	response, err := NewResponse(zs[:]...)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return commitment, response, nil
}

// SpecialSoundness returns the protocol extraction parameter.
func (*Protocol) SpecialSoundness() uint {
	return 2
}

// SoundnessError returns the statistical soundness error in bits.
func (*Protocol) SoundnessError() uint {
	return m
}

// GetChallengeBytesLength returns the challenge size in bytes.
func (*Protocol) GetChallengeBytesLength() int {
	return challengeBytes
}

// ValidateStatement checks that the witness trapdoor key matches the statement.
func (*Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if err := validateWitness(statement, witness); err != nil {
		return errs.Wrap(err).WithMessage("invalid witness")
	}
	return nil
}

func challengeBit(challenge sigma.ChallengeBytes, i int) uint8 {
	return (challenge[i/8] >> uint(i%8)) & 1
}
