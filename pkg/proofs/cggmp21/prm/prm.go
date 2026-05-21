package prm

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	// Name identifies the Pedersen parameters proof.
	Name sigma.Name = "CGGMP21_PedersenParameters"

	challengeBytes = base.ComputationalSecurityBytesCeil
	m              = challengeBytes * 8
)

// Statement is the public statement for the proof.
//
// The public input in Figure 13 is the Pedersen parameter tuple (N, s, t).
// This implementation carries it as an intcom commitment key.
type Statement struct {
	CommitmentKey *intcom.CommitmentKey
}

// NewStatement constructs a Pedersen parameters statement.
func NewStatement(commitmentKey *intcom.CommitmentKey) (*Statement, error) {
	statement := &Statement{CommitmentKey: commitmentKey}
	if err := validateStatement(statement); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	return statement, nil
}

// Bytes serialises the statement for transcript binding.
func (s *Statement) Bytes() []byte {
	if s == nil || s.CommitmentKey == nil {
		return nil
	}
	ss := s.CommitmentKey.S()
	t := s.CommitmentKey.T()
	if ss == nil || t == nil {
		return nil
	}

	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, ss.Group().Modulus().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, ss.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, t.Bytes())
	return out
}

// Witness contains the Pedersen parameters trapdoor.
type Witness struct {
	TrapdoorKey *intcom.TrapdoorKey
}

// NewWitness constructs a Pedersen parameters witness.
func NewWitness(trapdoorKey *intcom.TrapdoorKey) (*Witness, error) {
	if trapdoorKey == nil {
		return nil, ErrInvalidArgument.WithMessage("trapdoorKey must not be nil")
	}
	return &Witness{TrapdoorKey: trapdoorKey}, nil
}

// Bytes serialises the witness.
func (w *Witness) Bytes() []byte {
	if w == nil || w.TrapdoorKey == nil || w.TrapdoorKey.Lambda() == nil {
		return nil
	}
	group := w.TrapdoorKey.Group()
	if group == nil {
		return nil
	}

	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, group.Modulus().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, w.TrapdoorKey.Lambda().Bytes())
	return out
}

// Commitment holds the prover's first-round values.
type Commitment struct {
	A [m]*znstar.RSAGroupElementUnknownOrder `cbor:"a"`
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment) Bytes() []byte {
	if c == nil {
		return nil
	}

	out := binary.LittleEndian.AppendUint64(nil, uint64(len(c.A)))
	for _, a := range &c.A {
		var aBytes []byte
		if a != nil {
			aBytes = a.Bytes()
		}
		out = sliceutils.AppendLengthPrefixed(out, aBytes)
	}
	return out
}

// State stores the prover's internal randomness between rounds.
type State struct {
	Alpha [m]*num.Uint
}

// Response holds the prover responses.
type Response struct {
	Z [m]*num.Int `cbor:"z"`
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	if r == nil {
		return nil
	}

	out := binary.LittleEndian.AppendUint64(nil, uint64(len(r.Z)))
	for _, z := range &r.Z {
		var zBytes []byte
		if z != nil {
			zBytes = z.TwosComplementBytesBE()
		}
		out = sliceutils.AppendLengthPrefixed(out, zBytes)
	}
	return out
}

// Protocol implements the CGGMP21 Pedersen parameters proof.
type Protocol struct {
	prng io.Reader
}

// NewProtocol constructs a CGGMP21 Pedersen parameters proof instance.
func NewProtocol(prng io.Reader) (*Protocol, error) {
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng must not be nil")
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

	t, err := witness.TrapdoorKey.T().LearnOrder(witness.TrapdoorKey.Group())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not learn t order")
	}
	phi, err := phiFromGroup(witness.TrapdoorKey.Group())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute phi(N)")
	}
	zPhi, err := num.NewZMod(phi)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create Z/phi(N)Z")
	}

	commitment := &Commitment{}
	state := &State{}
	for i := range &commitment.A {
		alpha, err := zPhi.Random(p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample alpha")
		}
		commitment.A[i] = t.Exp(alpha.Nat()).ForgetOrder()
		state.Alpha[i] = alpha
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
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	t, err := witness.TrapdoorKey.T().LearnOrder(witness.TrapdoorKey.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn t order")
	}
	phi, err := phiFromGroup(witness.TrapdoorKey.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute phi(N)")
	}
	lambda := witness.TrapdoorKey.Lambda().Lift().Mod(phi)

	response := &Response{}
	for i := range &response.Z {
		alpha := state.Alpha[i]
		if alpha == nil {
			return nil, ErrInvalidArgument.WithMessage("state alpha is nil")
		}
		if !alpha.Modulus().Equal(phi) {
			return nil, ErrValidationFailed.WithMessage("state alpha has wrong modulus")
		}
		expected := t.Exp(alpha.Nat()).ForgetOrder()
		if !expected.Equal(commitment.A[i]) {
			return nil, ErrValidationFailed.WithMessage("commitment and state mismatch")
		}

		if challengeBit(challenge, i) != 0 {
			response.Z[i] = alpha.Add(lambda).Lift()
		} else {
			response.Z[i] = alpha.Lift()
		}
	}
	return response, nil
}

// Verify checks a prover response against the statement and commitment.
func (*Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	if err := validateStatement(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := validateCommitment(statement, commitment); err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment")
	}
	if response == nil {
		return ErrInvalidArgument.WithMessage("response must not be nil")
	}
	if len(challenge) != challengeBytes {
		return ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	s := statement.CommitmentKey.S()
	t := statement.CommitmentKey.T()
	n := statement.CommitmentKey.Group().Modulus().Nat()
	for i, z := range &response.Z {
		if z == nil {
			return ErrVerificationFailed.WithMessage("response z is nil")
		}
		// Honest responses satisfy z < phi(N) < N, and simulator responses are
		// smaller; reject huge parsed exponents before modular exponentiation.
		if !z.Abs().IsLessThanOrEqual(n) {
			return ErrVerificationFailed.WithMessage("response z is out of range")
		}

		lhs := t.ExpI(z)
		rhs := commitment.A[i]
		if challengeBit(challenge, i) == 1 {
			rhs = rhs.Mul(s)
		}
		if !lhs.Equal(rhs) {
			return ErrVerificationFailed.WithMessage("response does not satisfy verification equation")
		}
	}
	return nil
}

// RunSimulator creates an honest-verifier simulated transcript for a fixed challenge.
func (p *Protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	if err := validateStatement(statement); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	if len(challenge) != challengeBytes {
		return nil, nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	sInv, err := statement.CommitmentKey.S().TryInv()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not invert s")
	}
	t := statement.CommitmentKey.T()
	n := statement.CommitmentKey.Group().Modulus()
	low, high := symmetricModulusRange(n)

	commitment := &Commitment{}
	response := &Response{}
	for i := range &commitment.A {
		z, err := num.Z().Random(low, high, p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not sample simulator response")
		}
		a := t.ExpI(z)
		if challengeBit(challenge, i) == 1 {
			a = a.Mul(sInv)
		}

		commitment.A[i] = a
		response.Z[i] = z
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

// ValidateStatement checks that the public parameters are well-formed and that
// the witness trapdoor key matches them.
func (*Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if err := validateStatement(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := validateWitness(statement, witness); err != nil {
		return errs.Wrap(err).WithMessage("invalid witness")
	}
	return nil
}

func challengeBit(challenge sigma.ChallengeBytes, i int) uint8 {
	return (challenge[i/8] >> uint(i%8)) & 1
}
