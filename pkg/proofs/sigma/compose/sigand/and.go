// Package sigand implements AND composition of sigma protocols.
//
// AND composition allows a prover to demonstrate knowledge of valid witnesses
// for ALL statements simultaneously. Unlike OR composition, the prover must
// know witnesses for every statement in the composition.
//
// The verifier sends a single challenge, and the same challenge is used for
// all sub-protocols. This ensures the prover cannot selectively respond to
// different challenges for different statements.
//
// The package provides two composition variants:
//   - Compose: n-way composition using the same protocol type for all statements
//   - CartesianCompose: binary composition allowing different protocol types
package sigand

import (
	"encoding/binary"
	"fmt"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Statement represents an n-way AND-composed statement as a slice of individual statements.
// The prover claims to know valid witnesses for all statements in the slice.
type Statement[X sigma.Statement] []X

func (s Statement[X]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x X) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(s))),
		s...,
	)
}

var _ sigma.Statement = (Statement[sigma.Statement])(nil)

// Witness represents an n-way AND-composed witness as a slice of individual witnesses.
// Every witness must be valid for its corresponding statement in AND composition.
type Witness[W sigma.Witness] []W

func (w Witness[W]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x W) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(w))),
		w...,
	)
}

var _ sigma.Witness = (Witness[sigma.Witness])(nil)

// Commitment represents the prover's commitments for all branches in AND composition.
type Commitment[A sigma.Commitment] []A

func (c Commitment[A]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x A) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(c))),
		c...,
	)
}

var _ sigma.Commitment = (Commitment[sigma.Commitment])(nil)

// State holds the prover's internal states for all branches in AND composition.
// Each element corresponds to the prover state for the respective sub-protocol.
type State[S sigma.State] []S

var _ sigma.State = (State[sigma.State])(nil)

// Response contains the prover's responses for all branches in AND composition.
// Each element is computed using the same verifier challenge.
type Response[Z sigma.Response] []Z

func (r Response[Z]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x Z) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(r))),
		r...,
	)
}

var _ sigma.Response = (Response[sigma.Response])(nil)

// ComposeStatements creates an AND-composed statement from individual statements.
// All statements will be proven simultaneously using the same challenge.
func ComposeStatements[X sigma.Statement](statements ...X) Statement[X] {
	return statements
}

// ComposeWitnesses creates an AND-composed witness from individual witnesses.
// Every witness must be valid for its corresponding statement.
func ComposeWitnesses[W sigma.Witness](witnesses ...W) Witness[W] {
	return witnesses
}

type protocol[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] []sigma.Protocol[X, W, A, S, Z]

// Compose creates an n-way AND composition of a sigma protocol.
//
// The prover demonstrates knowledge of valid witnesses for all n statements
// simultaneously. The verifier sends a single challenge, which is used
// identically for all sub-protocol instances.
//
// Parameters:
//   - p: The sigma protocol to compose (used for all statements)
//   - count: The number of statements to compose (must be positive)
//
// Returns an error if p is nil or count is zero.
func Compose[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](
	p sigma.Protocol[X, W, A, S, Z], count uint,
) (sigma.Protocol[Statement[X], Witness[W], Commitment[A], State[S], Response[Z]], error) {
	if p == nil {
		return nil, ErrIsNil.WithMessage("protocol is nil")
	}
	if count == 0 {
		return nil, ErrInvalidArgument.WithMessage("count must be positive")
	}
	return sliceutils.Repeat[protocol[X, W, A, S, Z]](p, int(count)), nil
}

// ComputeProverCommitment generates the prover's first message in the AND composition.
//
// This computes commitments for all branches in parallel using the underlying protocol.
func (p protocol[X, W, A, S, Z]) ComputeProverCommitment(statement Statement[X], witness Witness[W]) (Commitment[A], State[S], error) {
	if len(statement) != len(p) {
		return nil, nil, ErrInvalidLength.WithMessage("invalid number of statements")
	}
	if len(witness) != len(p) {
		return nil, nil, ErrInvalidLength.WithMessage("invalid number of witnesses")
	}
	a := make(Commitment[A], len(p))
	s := make(State[S], len(p))
	var eg errgroup.Group
	for i, sigmai := range p {
		eg.Go(func() error {
			var err error
			a[i], s[i], err = sigmai.ComputeProverCommitment(statement[i], witness[i])
			if err != nil {
				return errs2.Wrap(err).WithMessage("failed to compute prover commitment")
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot compute commitments")
	}
	return a, s, nil
}

// ComputeProverResponse generates the prover's response to the verifier's challenge.
//
// The same challenge is used for all branches, computed in parallel.
func (p protocol[X, W, A, S, Z]) ComputeProverResponse(statement Statement[X], witness Witness[W], commitment Commitment[A], state State[S], challengeBytes sigma.ChallengeBytes) (Response[Z], error) {
	if len(statement) != len(p) {
		return nil, ErrInvalidLength.WithMessage("invalid number of statements")
	}
	if len(witness) != len(p) {
		return nil, ErrInvalidLength.WithMessage("invalid number of witnesses")
	}
	if len(commitment) != len(p) {
		return nil, ErrInvalidLength.WithMessage("invalid number of commitments")
	}
	if len(state) != len(p) {
		return nil, ErrInvalidLength.WithMessage("invalid number of states")
	}
	z := make(Response[Z], len(p))
	var eg errgroup.Group
	for i, sigmai := range p {
		eg.Go(func() error {
			var err error
			z[i], err = sigmai.ComputeProverResponse(statement[i], witness[i], commitment[i], state[i], challengeBytes)
			if err != nil {
				return errs2.Wrap(err).WithMessage("failed to compute prover response")
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot compute responses")
	}
	return z, nil
}

// Verify checks that the AND proof is valid.
//
// Each branch's transcript is verified using the same challenge in parallel.
func (p protocol[X, W, A, S, Z]) Verify(statement Statement[X], commitment Commitment[A], challengeBytes sigma.ChallengeBytes, response Response[Z]) error {
	if len(statement) != len(p) {
		return ErrInvalidLength.WithMessage("invalid number of statements")
	}
	if len(commitment) != len(p) {
		return ErrInvalidLength.WithMessage("invalid number of commitments")
	}
	if len(response) != len(p) {
		return ErrInvalidLength.WithMessage("invalid number of responses")
	}
	var eg errgroup.Group
	for i, sigmai := range p {
		eg.Go(func() error {
			return sigmai.Verify(statement[i], commitment[i], challengeBytes, response[i])
		})
	}
	if err := eg.Wait(); err != nil {
		return errs2.Wrap(err).WithMessage("verification failed")
	}
	return nil
}

// RunSimulator produces a simulated transcript for the AND composition.
//
// This runs the simulator for each branch in parallel using the same challenge.
func (p protocol[X, W, A, S, Z]) RunSimulator(statement Statement[X], challengeBytes sigma.ChallengeBytes) (Commitment[A], Response[Z], error) {
	if len(statement) != len(p) {
		return nil, nil, ErrInvalidLength.WithMessage("invalid number of statements")
	}
	a := make(Commitment[A], len(p))
	s := make(Response[Z], len(p))
	var eg errgroup.Group
	for i, sigmai := range p {
		eg.Go(func() error {
			var err error
			a[i], s[i], err = sigmai.RunSimulator(statement[i], challengeBytes)
			if err != nil {
				return errs2.Wrap(err).WithMessage("failed to run simulator")
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot run simulator")
	}
	return a, s, nil
}

// SpecialSoundness returns the special soundness parameter of the composed protocol.
func (p protocol[X, W, A, S, Z]) SpecialSoundness() uint {
	return p[0].SpecialSoundness()
}

// GetChallengeBytesLength returns the challenge length in bytes for the composed protocol.
func (p protocol[X, W, A, S, Z]) GetChallengeBytesLength() int {
	return p[0].GetChallengeBytesLength()
}

// SoundnessError returns the soundness error of the composed protocol.
func (p protocol[X, W, A, S, Z]) SoundnessError() uint {
	return p[0].SoundnessError()
}

// ValidateStatement checks that all statement/witness pairs are valid.
// For AND composition, every pair must be valid.
func (p protocol[X, W, A, S, Z]) ValidateStatement(statement Statement[X], witness Witness[W]) error {
	if len(statement) != len(p) {
		return ErrInvalidLength.WithMessage("invalid number of statements")
	}
	if len(witness) != len(p) {
		return ErrInvalidLength.WithMessage("invalid number of witnesses")
	}
	for i := range p {
		if err := p[i].ValidateStatement(statement[i], witness[i]); err != nil {
			return errs2.Wrap(err).WithMessage("invalid statement/witness at index %d", i)
		}
	}
	return nil
}

// Name returns a human-readable name for the composed protocol.
func (p protocol[X, W, A, S, Z]) Name() sigma.Name {
	return sigma.Name(fmt.Sprintf("(%s)^%d", p[0].Name(), len(p)))
}

// Sentinel errors for the sigand package.
var (
	// ErrIsNil indicates a nil argument was provided where a non-nil value was required.
	ErrIsNil = errs2.New("is nil")
	// ErrInvalidArgument indicates an invalid argument value was provided.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrInvalidLength indicates a slice has incorrect length for the operation.
	ErrInvalidLength = errs2.New("invalid length")
)
