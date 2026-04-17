package sigand

import (
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Statement represents an n-way AND-composed statement as a slice of individual statements.
// The prover claims to know valid witnesses for all statements in the slice.
type Statement[X sigma.Statement] []X

func (x Statement[X]) Bytes() []byte {
	xs := sliceutils.Map(x, func(in X) []byte { return in.Bytes() })
	out := []byte{}
	return sliceutils.AppendLengthPrefixedSlices(out, xs...)
}

var _ sigma.Statement = (Statement[sigma.Statement])(nil)

// Witness represents an n-way AND-composed witness as a slice of individual witnesses.
// Every witness must be valid for its corresponding statement in AND composition.
type Witness[W sigma.Witness] []W

func (w Witness[W]) Bytes() []byte {
	ws := sliceutils.Map(w, func(in W) []byte { return in.Bytes() })
	out := []byte{}
	return sliceutils.AppendLengthPrefixedSlices(out, ws...)
}

var _ sigma.Witness = (Witness[sigma.Witness])(nil)

// Commitment represents the prover's commitments for all branches in AND composition.
type Commitment[A sigma.Commitment] []A

func (a Commitment[A]) Bytes() []byte {
	as := sliceutils.Map(a, func(in A) []byte { return in.Bytes() })
	out := []byte{}
	return sliceutils.AppendLengthPrefixedSlices(out, as...)
}

var _ sigma.Commitment = (Commitment[sigma.Commitment])(nil)

// State holds the prover's internal states for all branches in AND composition.
// Each element corresponds to the prover state for the respective sub-protocol.
type State[S sigma.State] []S

var _ sigma.State = (State[sigma.State])(nil)

// Response contains the prover's responses for all branches in AND composition.
// Each element is computed using the same verifier challenge.
type Response[Z sigma.Response] []Z

func (z Response[Z]) Bytes() []byte {
	zs := sliceutils.Map(z, func(in Z) []byte { return in.Bytes() })
	out := []byte{}
	return sliceutils.AppendLengthPrefixedSlices(out, zs...)
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

type Protocol[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	protocols []sigma.Protocol[X, W, A, S, Z]
	name      sigma.Name
}

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
) (*Protocol[X, W, A, S, Z], error) {
	if p == nil {
		return nil, ErrIsNil.WithMessage("protocol is nil")
	}
	if count == 0 {
		return nil, ErrInvalidArgument.WithMessage("count must be positive")
	}
	name := sigma.Name(fmt.Sprintf("(%s)^%d", p.Name(), count))
	out, err := ComposeNamed(name, p, count)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compose protocols")
	}
	return out, nil
}

// ComposeNamed is the same as Compose but uses the provided name as the
// composed protocol's Name instead of deriving one from the underlying
// protocol. Use this when the composition is the implementation of a
// named higher-level protocol and should be identified accordingly.
func ComposeNamed[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](
	name sigma.Name, p sigma.Protocol[X, W, A, S, Z], count uint,
) (*Protocol[X, W, A, S, Z], error) {
	if p == nil {
		return nil, ErrIsNil.WithMessage("protocol is nil")
	}
	if count == 0 {
		return nil, ErrInvalidArgument.WithMessage("count must be positive")
	}
	return &Protocol[X, W, A, S, Z]{name: name, protocols: sliceutils.Repeat[[]sigma.Protocol[X, W, A, S, Z]](p, int(count))}, nil
}

// ComputeProverCommitment generates the prover's first message in the AND composition.
//
// This computes commitments for all branches in parallel using the underlying protocol.
func (p *Protocol[X, W, A, S, Z]) ComputeProverCommitment(statement Statement[X], witness Witness[W]) (Commitment[A], State[S], error) {
	if len(statement) != len(p.protocols) {
		return nil, nil, ErrInvalidLength.WithMessage("invalid number of statements")
	}
	if len(witness) != len(p.protocols) {
		return nil, nil, ErrInvalidLength.WithMessage("invalid number of witnesses")
	}
	a := make(Commitment[A], len(p.protocols))
	s := make(State[S], len(p.protocols))
	var eg errgroup.Group
	for i, sigmai := range p.protocols {
		eg.Go(func() error {
			var err error
			a[i], s[i], err = sigmai.ComputeProverCommitment(statement[i], witness[i])
			if err != nil {
				return errs.Wrap(err).WithMessage("failed to compute prover commitment")
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute commitments")
	}
	return a, s, nil
}

// ComputeProverResponse generates the prover's response to the verifier's challenge.
//
// The same challenge is used for all branches, computed in parallel.
func (p *Protocol[X, W, A, S, Z]) ComputeProverResponse(statement Statement[X], witness Witness[W], commitment Commitment[A], state State[S], challengeBytes sigma.ChallengeBytes) (Response[Z], error) {
	if len(statement) != len(p.protocols) {
		return nil, ErrInvalidLength.WithMessage("invalid number of statements")
	}
	if len(witness) != len(p.protocols) {
		return nil, ErrInvalidLength.WithMessage("invalid number of witnesses")
	}
	if len(commitment) != len(p.protocols) {
		return nil, ErrInvalidLength.WithMessage("invalid number of commitments")
	}
	if len(state) != len(p.protocols) {
		return nil, ErrInvalidLength.WithMessage("invalid number of states")
	}
	z := make(Response[Z], len(p.protocols))
	var eg errgroup.Group
	for i, sigmai := range p.protocols {
		eg.Go(func() error {
			var err error
			z[i], err = sigmai.ComputeProverResponse(statement[i], witness[i], commitment[i], state[i], challengeBytes)
			if err != nil {
				return errs.Wrap(err).WithMessage("failed to compute prover response")
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute responses")
	}
	return z, nil
}

// Verify checks that the AND proof is valid.
//
// Each branch's transcript is verified using the same challenge in parallel.
func (p *Protocol[X, W, A, S, Z]) Verify(statement Statement[X], commitment Commitment[A], challengeBytes sigma.ChallengeBytes, response Response[Z]) error {
	if len(statement) != len(p.protocols) {
		return ErrInvalidLength.WithMessage("invalid number of statements")
	}
	if len(commitment) != len(p.protocols) {
		return ErrInvalidLength.WithMessage("invalid number of commitments")
	}
	if len(response) != len(p.protocols) {
		return ErrInvalidLength.WithMessage("invalid number of responses")
	}
	var eg errgroup.Group
	for i, sigmai := range p.protocols {
		eg.Go(func() error {
			return sigmai.Verify(statement[i], commitment[i], challengeBytes, response[i])
		})
	}
	if err := eg.Wait(); err != nil {
		return errs.Wrap(err).WithMessage("verification failed")
	}
	return nil
}

// RunSimulator produces a simulated transcript for the AND composition.
//
// This runs the simulator for each branch in parallel using the same challenge.
func (p *Protocol[X, W, A, S, Z]) RunSimulator(statement Statement[X], challengeBytes sigma.ChallengeBytes) (Commitment[A], Response[Z], error) {
	if len(statement) != len(p.protocols) {
		return nil, nil, ErrInvalidLength.WithMessage("invalid number of statements")
	}
	a := make(Commitment[A], len(p.protocols))
	s := make(Response[Z], len(p.protocols))
	var eg errgroup.Group
	for i, sigmai := range p.protocols {
		eg.Go(func() error {
			var err error
			a[i], s[i], err = sigmai.RunSimulator(statement[i], challengeBytes)
			if err != nil {
				return errs.Wrap(err).WithMessage("failed to run simulator")
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run simulator")
	}
	return a, s, nil
}

// SpecialSoundness returns the special soundness parameter of the composed protocol.
func (p *Protocol[X, W, A, S, Z]) SpecialSoundness() uint {
	return p.protocols[0].SpecialSoundness()
}

// GetChallengeBytesLength returns the challenge length in bytes for the composed protocol.
func (p *Protocol[X, W, A, S, Z]) GetChallengeBytesLength() int {
	return p.protocols[0].GetChallengeBytesLength()
}

// SoundnessError returns the soundness error of the composed protocol.
func (p *Protocol[X, W, A, S, Z]) SoundnessError() uint {
	return p.protocols[0].SoundnessError()
}

// ValidateStatement checks that all statement/witness pairs are valid.
// For AND composition, every pair must be valid.
func (p *Protocol[X, W, A, S, Z]) ValidateStatement(statement Statement[X], witness Witness[W]) error {
	if len(statement) != len(p.protocols) {
		return ErrInvalidLength.WithMessage("invalid number of statements")
	}
	if len(witness) != len(p.protocols) {
		return ErrInvalidLength.WithMessage("invalid number of witnesses")
	}
	for i := range p.protocols {
		if err := p.protocols[i].ValidateStatement(statement[i], witness[i]); err != nil {
			return errs.Wrap(err).WithMessage("invalid statement/witness at index %d", i)
		}
	}
	return nil
}

// Name returns a human-readable name for the composed protocol.
func (p *Protocol[X, W, A, S, Z]) Name() sigma.Name {
	return p.name
}

// Sentinel errors for the sigand package.
var (
	// ErrIsNil indicates a nil argument was provided where a non-nil value was required.
	ErrIsNil = errs.New("is nil")
	// ErrInvalidArgument indicates an invalid argument value was provided.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrInvalidLength indicates a slice has incorrect length for the operation.
	ErrInvalidLength = errs.New("invalid length")
)
