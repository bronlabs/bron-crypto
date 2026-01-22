package sigand

import (
	"fmt"
	"slices"

	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// StatementCartesian represents a binary AND-composed statement with two potentially
// different statement types. The prover claims to know witnesses for both statements.
type StatementCartesian[X0, X1 sigma.Statement] struct {
	// X0 is the first statement.
	X0 X0
	// X1 is the second statement.
	X1 X1
}

func (s *StatementCartesian[X0, X1]) Bytes() []byte {
	return slices.Concat(s.X0.Bytes(), s.X1.Bytes())
}

var _ sigma.Statement = (*StatementCartesian[sigma.Statement, sigma.Statement])(nil)

// WitnessCartesian represents a binary AND-composed witness with two potentially
// different witness types. Both witnesses must be valid for their corresponding statements.
type WitnessCartesian[W0, W1 sigma.Witness] struct {
	// W0 is the witness for the first statement.
	W0 W0
	// W1 is the witness for the second statement.
	W1 W1
}

func (w *WitnessCartesian[W0, W1]) Bytes() []byte {
	return slices.Concat(w.W0.Bytes(), w.W1.Bytes())
}

var _ sigma.Witness = (*WitnessCartesian[sigma.Witness, sigma.Witness])(nil)

// CommitmentCartesian represents a binary AND-composed commitment.
type CommitmentCartesian[A0, A1 sigma.Commitment] struct {
	// A0 is the commitment for the first branch.
	A0 A0
	// A1 is the commitment for the second branch.
	A1 A1
}

func (c *CommitmentCartesian[A0, A1]) Bytes() []byte {
	return slices.Concat(c.A0.Bytes(), c.A1.Bytes())
}

var _ sigma.Commitment = (*CommitmentCartesian[sigma.Commitment, sigma.Commitment])(nil)

// StateCartesian holds the prover's internal state for binary AND composition.
type StateCartesian[S0, S1 sigma.State] struct {
	// S0 is the prover state for the first branch.
	S0 S0
	// S1 is the prover state for the second branch.
	S1 S1
}

var _ sigma.State = (*StateCartesian[sigma.State, sigma.State])(nil)

// ResponseCartesian represents the prover's response for binary AND composition.
type ResponseCartesian[Z0, Z1 sigma.Response] struct {
	// Z0 is the response for the first branch.
	Z0 Z0
	// Z1 is the response for the second branch.
	Z1 Z1
}

func (r *ResponseCartesian[Z0, Z1]) Bytes() []byte {
	return slices.Concat(r.Z0.Bytes(), r.Z1.Bytes())
}

var _ sigma.Response = (*ResponseCartesian[sigma.Response, sigma.Response])(nil)

// CartesianComposeStatements creates a binary AND-composed statement from two statements.
func CartesianComposeStatements[X0, X1 sigma.Statement](statement0 X0, statement1 X1) *StatementCartesian[X0, X1] {
	return &StatementCartesian[X0, X1]{
		X0: statement0,
		X1: statement1,
	}
}

// CartesianComposeWitnesses creates a binary AND-composed witness from two witnesses.
// Both witnesses must be valid for their corresponding statements.
func CartesianComposeWitnesses[W0, W1 sigma.Witness](witness0 W0, witness1 W1) *WitnessCartesian[W0, W1] {
	return &WitnessCartesian[W0, W1]{
		W0: witness0,
		W1: witness1,
	}
}

type protocolCartesian[X0, X1 sigma.Statement, W0, W1 sigma.Witness, A0, A1 sigma.Commitment, S0, S1 sigma.State, Z0, Z1 sigma.Response] struct {
	sigma0               sigma.Protocol[X0, W0, A0, S0, Z0]
	sigma1               sigma.Protocol[X1, W1, A1, S1, Z1]
	challengeBytesLength int
}

// CartesianCompose creates a binary AND composition of two potentially different sigma protocols.
//
// This allows proving knowledge of witnesses for two statements simultaneously,
// even when the statements use different underlying protocols. The same challenge
// is used for both sub-protocols.
//
// Parameters:
//   - sigma0: The sigma protocol for the first statement
//   - sigma1: The sigma protocol for the second statement
func CartesianCompose[X0, X1 sigma.Statement, W0, W1 sigma.Witness, A0, A1 sigma.Commitment, S0, S1 sigma.State, Z0, Z1 sigma.Response](sigma0 sigma.Protocol[X0, W0, A0, S0, Z0], sigma1 sigma.Protocol[X1, W1, A1, S1, Z1]) sigma.Protocol[*StatementCartesian[X0, X1], *WitnessCartesian[W0, W1], *CommitmentCartesian[A0, A1], *StateCartesian[S0, S1], *ResponseCartesian[Z0, Z1]] {
	challengeBytesLength := max(sigma0.GetChallengeBytesLength(), sigma1.GetChallengeBytesLength())

	return &protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]{
		sigma0:               sigma0,
		sigma1:               sigma1,
		challengeBytesLength: challengeBytesLength,
	}
}

// ComputeProverCommitment generates the prover's first message in the binary AND composition.
//
// This computes commitments for both branches using their respective protocols.
func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverCommitment(statement *StatementCartesian[X0, X1], witness *WitnessCartesian[W0, W1]) (*CommitmentCartesian[A0, A1], *StateCartesian[S0, S1], error) {
	var err error
	a := new(CommitmentCartesian[A0, A1])
	s := new(StateCartesian[S0, S1])

	if a.A0, s.S0, err = p.sigma0.ComputeProverCommitment(statement.X0, witness.W0); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute commitment")
	}
	if a.A1, s.S1, err = p.sigma1.ComputeProverCommitment(statement.X1, witness.W1); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute commitment")
	}

	return a, s, nil
}

// ComputeProverResponse generates the prover's response to the verifier's challenge.
//
// The same challenge is used for both branches.
func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ComputeProverResponse(statement *StatementCartesian[X0, X1], witness *WitnessCartesian[W0, W1], commitment *CommitmentCartesian[A0, A1], state *StateCartesian[S0, S1], challengeBytes sigma.ChallengeBytes) (*ResponseCartesian[Z0, Z1], error) {
	var err error
	z := new(ResponseCartesian[Z0, Z1])

	if z.Z0, err = p.sigma0.ComputeProverResponse(statement.X0, witness.W0, commitment.A0, state.S0, challengeBytes[:p.sigma0.GetChallengeBytesLength()]); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute response")
	}
	if z.Z1, err = p.sigma1.ComputeProverResponse(statement.X1, witness.W1, commitment.A1, state.S1, challengeBytes[:p.sigma1.GetChallengeBytesLength()]); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute response")
	}

	return z, nil
}

// Verify checks that the binary AND proof is valid.
//
// Both branch transcripts are verified using the same challenge.
func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Verify(statement *StatementCartesian[X0, X1], commitment *CommitmentCartesian[A0, A1], challengeBytes sigma.ChallengeBytes, response *ResponseCartesian[Z0, Z1]) error {
	if err := p.sigma0.Verify(statement.X0, commitment.A0, challengeBytes[:p.sigma0.GetChallengeBytesLength()], response.Z0); err != nil {
		return errs.Wrap(err).WithMessage("verification failed")
	}
	if err := p.sigma1.Verify(statement.X1, commitment.A1, challengeBytes[:p.sigma1.GetChallengeBytesLength()], response.Z1); err != nil {
		return errs.Wrap(err).WithMessage("verification failed")
	}

	return nil
}

// RunSimulator produces a simulated transcript for the binary AND composition.
//
// This runs the simulator for both branches using the same challenge.
func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) RunSimulator(statement *StatementCartesian[X0, X1], challengeBytes sigma.ChallengeBytes) (*CommitmentCartesian[A0, A1], *ResponseCartesian[Z0, Z1], error) {
	var err error
	a := new(CommitmentCartesian[A0, A1])
	z := new(ResponseCartesian[Z0, Z1])

	if a.A0, z.Z0, err = p.sigma0.RunSimulator(statement.X0, challengeBytes[:p.sigma0.GetChallengeBytesLength()]); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run simulator")
	}
	if a.A1, z.Z1, err = p.sigma1.RunSimulator(statement.X1, challengeBytes[:p.sigma1.GetChallengeBytesLength()]); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run simulator")
	}

	return a, z, nil
}

// SpecialSoundness returns the special soundness parameter of the composed protocol.
func (p *protocolCartesian[_, _, _, _, _, _, _, _, _, _]) SpecialSoundness() uint {
	return max(p.sigma0.SpecialSoundness(), p.sigma1.SpecialSoundness())
}

// GetChallengeBytesLength returns the challenge length in bytes for the composed protocol.
func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) GetChallengeBytesLength() int {
	return p.challengeBytesLength
}

// SoundnessError returns the soundness error of the composed protocol,
// which is the minimum of the two underlying protocols' soundness errors.
func (p protocolCartesian[_, _, _, _, _, _, _, _, _, _]) SoundnessError() uint {
	return min(p.sigma0.SoundnessError(), p.sigma1.SoundnessError())
}

// ValidateStatement checks that both statement/witness pairs are valid.
// For AND composition, both pairs must be valid.
func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) ValidateStatement(statement *StatementCartesian[X0, X1], witness *WitnessCartesian[W0, W1]) error {
	if err := p.sigma0.ValidateStatement(statement.X0, witness.W0); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := p.sigma1.ValidateStatement(statement.X1, witness.W1); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}

	return nil
}

// Name returns a human-readable name for the composed protocol.
func (p *protocolCartesian[X0, X1, W0, W1, A0, A1, S0, S1, Z0, Z1]) Name() sigma.Name {
	return sigma.Name(fmt.Sprintf("(%s)_AND_(%s)", p.sigma0.Name(), p.sigma1.Name()))
}
