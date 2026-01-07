// Package sigor implements OR composition of sigma protocols.
//
// OR composition allows a prover to demonstrate knowledge of a witness for at least one
// of n statements, without revealing which statement they know the witness for.
// This provides witness indistinguishability - the verifier cannot determine which
// branch the prover actually knows.
//
// The composition uses the XOR technique: challenges for all branches XOR together
// to equal the verifier's challenge. The prover runs the real protocol for the branch
// they know, and simulates the other branches using the simulator.
package sigor

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"golang.org/x/sync/errgroup"
)

// Statement represents an OR-composed statement consisting of n sub-statements.
// The prover claims to know a witness for at least one of these statements.
type Statement[X sigma.Statement] []X

// Bytes returns the canonical byte representation of the composed statement.
func (s Statement[X]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x X) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(s))),
		s...,
	)
}

var _ sigma.Statement = (Statement[sigma.Statement])(nil)

// Witness represents an OR-composed witness consisting of n sub-witnesses.
// Only one of these witnesses needs to be valid for the corresponding statement.
type Witness[W sigma.Witness] []W

// Bytes returns the canonical byte representation of the composed witness.
func (w Witness[W]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x W) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(w))),
		w...,
	)
}

var _ sigma.Witness = (Witness[sigma.Witness])(nil)

// Commitment represents an OR-composed commitment consisting of n sub-commitments,
// one for each branch of the OR composition.
type Commitment[A sigma.Commitment] []A

// Bytes returns the canonical byte representation of the composed commitment.
func (c Commitment[A]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x A) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(c))),
		c...,
	)
}

var _ sigma.Commitment = (Commitment[sigma.Commitment])(nil)

// State holds the prover's internal state between commitment and response phases.
// It stores information needed to compute the final response, including which branch
// is the "true" branch and the simulated responses for false branches.
type State[S sigma.State, Z sigma.Response] struct {
	// B is the index of the branch for which the prover knows a valid witness.
	B uint
	// S contains the prover states for each branch. Only S[B] is meaningful;
	// other entries are zero values since those branches are simulated.
	S []S
	// E contains the random challenges used for simulating false branches.
	// E[i] is the challenge used for branch i when i != B. E[B] is unused.
	E [][]byte
	// Z contains the simulated responses for false branches.
	// Z[i] is the simulated response for branch i when i != B. Z[B] is unused.
	Z []Z
}

var _ sigma.State = (*State[sigma.State, sigma.Response])(nil)

// Response represents the prover's response in the OR composition.
// It contains challenges and responses for all branches, satisfying the XOR constraint.
type Response[Z sigma.Response] struct {
	// E contains the challenges for each branch. These satisfy the constraint:
	// E[0] XOR E[1] XOR ... XOR E[n-1] = verifier's challenge.
	E [][]byte
	// Z contains the responses for each branch. For the true branch, this is
	// computed honestly; for false branches, these are simulated responses.
	Z []Z
}

// Bytes returns the canonical byte representation of the response.
func (r Response[Z]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x Z) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(r.Z))),
		r.Z...,
	)
}

var _ sigma.Response = (*Response[sigma.Response])(nil)

// ComposeStatements creates an OR-composed statement from individual statements.
func ComposeStatements[X sigma.Statement](statements ...X) Statement[X] {
	return statements
}

// ComposeWitnesses creates an OR-composed witness from individual witnesses.
// Only one witness needs to be valid for its corresponding statement.
func ComposeWitnesses[W sigma.Witness](witnesses ...W) Witness[W] {
	return witnesses
}

type protocol[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sigmas []sigma.Protocol[X, W, A, S, Z]
	prng   io.Reader
}

// Compose creates an n-way OR composition of sigma protocols.
//
// The resulting protocol proves knowledge of a witness for at least one of n statements,
// without revealing which one. This is achieved using the XOR technique where challenges
// for all branches XOR to equal the verifier's challenge.
//
// Parameters:
//   - p: The base sigma protocol to compose (used for all n branches)
//   - count: Number of branches (must be >= 2)
//   - prng: Cryptographically secure random number generator
//
// Returns an error if p is nil, prng is nil, or count < 2.
func Compose[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](
	p sigma.Protocol[X, W, A, S, Z], count uint, prng io.Reader,
) (sigma.Protocol[Statement[X], Witness[W], Commitment[A], *State[S, Z], *Response[Z]], error) {
	if p == nil || prng == nil {
		return nil, ErrIsNil.WithMessage("p or prng is nil")
	}
	if count < 2 {
		return nil, ErrInvalidArgument.WithMessage("count must be positive and greater than 2")
	}
	return &protocol[X, W, A, S, Z]{
		sigmas: sliceutils.Repeat[[]sigma.Protocol[X, W, A, S, Z]](p, int(count)),
		prng:   prng,
	}, nil
}

// SoundnessError returns the soundness error of the composed protocol,
// which equals the soundness error of the underlying protocol.
func (p *protocol[X, W, A, S, Z]) SoundnessError() uint {
	return p.sigmas[0].SoundnessError()
}

// ComputeProverCommitment generates the prover's first message in the OR composition.
//
// For the branch with a valid witness (the "true" branch), this computes a real
// commitment using the underlying protocol. For all other branches, it samples
// random challenges and runs the simulator to generate fake commitments and responses.
func (p *protocol[X, W, A, S, Z]) ComputeProverCommitment(statement Statement[X], witness Witness[W]) (Commitment[A], *State[S, Z], error) {
	if len(statement) != len(p.sigmas) {
		return nil, nil, ErrInvalidLength.WithMessage("invalid statement length")
	}
	if len(witness) != len(p.sigmas) {
		return nil, nil, ErrInvalidLength.WithMessage("invalid witness length")
	}

	a := make(Commitment[A], len(p.sigmas))
	s := &State[S, Z]{
		S: make([]S, len(p.sigmas)),
		E: make([][]byte, len(p.sigmas)),
		Z: make([]Z, len(p.sigmas)),
	}

	var err error
	s.B, err = p.getB(statement, witness)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot determine valid statement index")
	}

	// Sample random challenges for all false branches
	var eg errgroup.Group
	for i, sigmai := range p.sigmas {
		if i == int(s.B) {
			// True branch: compute real commitment
			eg.Go(func() error {
				var err error
				a[i], s.S[i], err = sigmai.ComputeProverCommitment(statement[i], witness[i])
				if err != nil {
					return errs2.Wrap(err)
				}
				return nil
			})
		} else {
			// False branch: sample random challenge and run simulator
			eg.Go(func() error {
				s.E[i] = make([]byte, p.GetChallengeBytesLength())
				_, err := io.ReadFull(p.prng, s.E[i])
				if err != nil {
					return errs2.Wrap(err)
				}
				var simErr error
				a[i], s.Z[i], simErr = sigmai.RunSimulator(statement[i], s.E[i][:sigmai.GetChallengeBytesLength()])
				if simErr != nil {
					return errs2.Wrap(simErr)
				}
				return nil
			})
		}
	}

	if err := eg.Wait(); err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	return a, s, nil
}

// ComputeProverResponse generates the prover's response to the verifier's challenge.
//
// The challenge for the true branch is computed so that all challenges XOR to the
// verifier's challenge: e_B = challenge XOR e_0 XOR ... XOR e_{n-1} (excluding e_B).
// The response for the true branch is then computed using the real protocol.
func (p *protocol[X, W, A, S, Z]) ComputeProverResponse(statement Statement[X], witness Witness[W], commitment Commitment[A], state *State[S, Z], challenge sigma.ChallengeBytes) (*Response[Z], error) {
	if len(statement) != len(p.sigmas) {
		return nil, ErrInvalidLength.WithMessage("invalid statement length")
	}
	if len(witness) != len(p.sigmas) {
		return nil, ErrInvalidLength.WithMessage("invalid witness length")
	}
	if len(commitment) != len(p.sigmas) {
		return nil, ErrInvalidLength.WithMessage("invalid commitment length")
	}
	if len(state.S) != len(p.sigmas) || len(state.Z) != len(p.sigmas) || len(state.E) != len(p.sigmas) {
		return nil, ErrInvalidLength.WithMessage("invalid state length")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, ErrInvalidLength.WithMessage("invalid challenge length")
	}

	z := &Response[Z]{
		E: make([][]byte, len(p.sigmas)),
		Z: make([]Z, len(p.sigmas)),
	}

	// Compute the challenge for the true branch so that XOR of all challenges equals verifier's challenge:
	// e_B = challenge XOR e_0 XOR e_1 XOR ... XOR e_{n-1} (excluding e_B)
	z.E[state.B] = make([]byte, p.GetChallengeBytesLength())
	copy(z.E[state.B], challenge)
	for i := range p.sigmas {
		if i != int(state.B) {
			z.E[i] = state.E[i]
			z.Z[i] = state.Z[i]
			subtle.XORBytes(z.E[state.B], z.E[state.B], state.E[i])
		}
	}

	// Compute response for the true branch
	var err error
	z.Z[state.B], err = p.sigmas[state.B].ComputeProverResponse(
		statement[state.B], witness[state.B], commitment[state.B], state.S[state.B],
		z.E[state.B][:p.sigmas[state.B].GetChallengeBytesLength()],
	)
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	return z, nil
}

// Verify checks that the OR proof is valid.
//
// Verification ensures: (1) the XOR of all branch challenges equals the verifier's
// challenge, and (2) each branch's transcript is accepting under the underlying protocol.
func (p *protocol[X, W, A, S, Z]) Verify(statement Statement[X], commitment Commitment[A], challenge sigma.ChallengeBytes, response *Response[Z]) error {
	if len(statement) != len(p.sigmas) {
		return ErrInvalidLength.WithMessage("invalid statement length")
	}
	if len(commitment) != len(p.sigmas) {
		return ErrInvalidLength.WithMessage("invalid commitment length")
	}
	if len(response.Z) != len(p.sigmas) {
		return ErrInvalidLength.WithMessage("invalid response length")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return ErrInvalidLength.WithMessage("invalid challenge length")
	}
	xoredChallenges := make([]byte, p.GetChallengeBytesLength())
	subtle.XORBytes(xoredChallenges, response.E[0], response.E[1])
	sliceutils.Reduce(
		response.E[2:],
		xoredChallenges,
		func(acc []byte, e []byte) []byte {
			subtle.XORBytes(acc, acc, e)
			return acc
		},
	)
	if ct.SliceEqual(challenge, xoredChallenges) == ct.False {
		return ErrVerification.WithMessage("verification failed")
	}

	var eg errgroup.Group
	for i, sigmai := range p.sigmas {
		eg.Go(func() error {
			return sigmai.Verify(statement[i], commitment[i], response.E[i][:sigmai.GetChallengeBytesLength()], response.Z[i])
		})
	}
	if err := eg.Wait(); err != nil {
		return errs2.Wrap(err).WithMessage("verification failed")
	}
	return nil
}

// RunSimulator produces a simulated transcript for the OR composition.
//
// This generates random challenges for all but the last branch, then computes
// the last challenge so that all challenges XOR to the given challenge.
// Each branch's transcript is then simulated using the underlying protocol's simulator.
func (p *protocol[X, W, A, S, Z]) RunSimulator(statement Statement[X], challenge sigma.ChallengeBytes) (Commitment[A], *Response[Z], error) {
	if len(statement) != len(p.sigmas) {
		return nil, nil, ErrInvalidLength.WithMessage("invalid statement length")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, nil, ErrInvalidLength.WithMessage("invalid challenge length")
	}

	a := make(Commitment[A], len(p.sigmas))
	z := &Response[Z]{
		E: make([][]byte, len(p.sigmas)),
		Z: make([]Z, len(p.sigmas)),
	}

	var eg errgroup.Group
	for i := range len(p.sigmas) - 1 {
		eg.Go(func() error {
			z.E[i] = make([]byte, p.GetChallengeBytesLength())
			_, err := io.ReadFull(p.prng, z.E[i])
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot sample challenges")
	}
	// Compute last challenge so that XOR of all challenges equals the verifier's challenge:
	// e_{n-1} = challenge XOR e_0 XOR e_1 XOR ... XOR e_{n-2}
	z.E[len(p.sigmas)-1] = make([]byte, p.GetChallengeBytesLength())
	subtle.XORBytes(z.E[len(p.sigmas)-1], challenge, z.E[0])
	for i := 1; i < len(p.sigmas)-1; i++ {
		subtle.XORBytes(z.E[len(p.sigmas)-1], z.E[len(p.sigmas)-1], z.E[i])
	}

	var eg2 errgroup.Group
	for i, sigmai := range p.sigmas {
		eg2.Go(func() error {
			var err error
			a[i], z.Z[i], err = sigmai.RunSimulator(statement[i], z.E[i][:sigmai.GetChallengeBytesLength()])
			if err != nil {
				return errs2.Wrap(err).WithMessage("cannot run simulator")
			}
			return nil
		})
	}
	if err := eg2.Wait(); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot compute responses")
	}
	return a, z, nil
}

// SpecialSoundness returns the special soundness parameter of the composed protocol.
func (p *protocol[X, W, A, S, Z]) SpecialSoundness() uint {
	return p.sigmas[0].SpecialSoundness()
}

// GetChallengeBytesLength returns the challenge length in bytes for the composed protocol.
func (p *protocol[X, W, A, S, Z]) GetChallengeBytesLength() int {
	return p.sigmas[0].GetChallengeBytesLength()
}

// ValidateStatement checks that at least one statement/witness pair is valid.
// For OR composition, only one valid pair is required (unlike AND composition).
func (p *protocol[X, W, A, S, Z]) ValidateStatement(statement Statement[X], witness Witness[W]) error {
	if len(statement) != len(p.sigmas) {
		return ErrInvalidLength.WithMessage("invalid statement length")
	}
	if len(witness) != len(p.sigmas) {
		return ErrInvalidLength.WithMessage("invalid witness length")
	}
	// For OR composition, at least one statement/witness pair must be valid
	for i, sigmai := range p.sigmas {
		if invalid := sigmai.ValidateStatement(statement[i], witness[i]); invalid == nil {
			return nil // Found a valid pair
		}
	}
	return ErrNotExactlyOneOutOfN.WithMessage("no valid statement/witness pair found")
}

// getB finds the index of the branch with a valid statement/witness pair.
// Returns an error if no valid pair is found.
func (p *protocol[X, W, A, S, Z]) getB(statement Statement[X], witness Witness[W]) (uint, error) {
	B := uint(len(p.sigmas)) // invalid value
	for i, sigmai := range p.sigmas {
		if invalid := sigmai.ValidateStatement(statement[i], witness[i]); invalid == nil {
			B = uint(i)
		}
	}
	if B == uint(len(p.sigmas)) {
		return 0, ErrNotExactlyOneOutOfN.WithStackFrame()
	}
	return B, nil
}

// Name returns a human-readable name for the composed protocol.
func (p *protocol[X, W, A, S, Z]) Name() sigma.Name {
	return sigma.Name(fmt.Sprintf("SigmaOR(%s)^%d", p.sigmas[0].Name(), len(p.sigmas)))
}

// Sentinel errors for the sigor package.
var (
	// ErrIsNil is returned when a required argument is nil.
	ErrIsNil = errs2.New("is nil")
	// ErrNotExactlyOneOutOfN is returned when no valid statement/witness pair is found.
	ErrNotExactlyOneOutOfN = errs2.New("not exactly one statement out of n is valid")
	// ErrInvalidLength is returned when input slices have incorrect lengths.
	ErrInvalidLength = errs2.New("invalid length")
	// ErrInvalidArgument is returned when an argument has an invalid value.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrVerification is returned when proof verification fails.
	ErrVerification = errs2.New("verification failed")
)
