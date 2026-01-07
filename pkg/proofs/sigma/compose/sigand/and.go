package sigand

import (
	"encoding/binary"
	"fmt"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

type Statement[X sigma.Statement] []X

func (s Statement[X]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x X) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(s))),
		s...,
	)
}

var _ sigma.Statement = (Statement[sigma.Statement])(nil)

type Witness[W sigma.Witness] []W

func (w Witness[W]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x W) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(w))),
		w...,
	)
}

var _ sigma.Witness = (Witness[sigma.Witness])(nil)

type Commitment[A sigma.Commitment] []A

func (c Commitment[A]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x A) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(c))),
		c...,
	)
}

var _ sigma.Commitment = (Commitment[sigma.Commitment])(nil)

type State[S sigma.State] []S

var _ sigma.State = (State[sigma.State])(nil)

type Response[Z sigma.Response] []Z

func (r Response[Z]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x Z) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(r))),
		r...,
	)
}

var _ sigma.Response = (Response[sigma.Response])(nil)

func ComposeStatements[X sigma.Statement](statements ...X) Statement[X] {
	return statements
}

func ComposeWitnesses[W sigma.Witness](witnesses ...W) Witness[W] {
	return witnesses
}

type protocol[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] []sigma.Protocol[X, W, A, S, Z]

func Compose[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](
	p sigma.Protocol[X, W, A, S, Z], count uint,
) (sigma.Protocol[Statement[X], Witness[W], Commitment[A], State[S], Response[Z]], error) {
	if p == nil {
		return nil, errs.NewArgument("protocol is nil")
	}
	if count == 0 {
		return nil, errs.NewArgument("count must be positive")
	}
	return sliceutils.Repeat[protocol[X, W, A, S, Z]](p, int(count)), nil
}

func (p protocol[X, W, A, S, Z]) ComputeProverCommitment(statement Statement[X], witness Witness[W]) (Commitment[A], State[S], error) {
	if len(statement) != len(p) {
		return nil, nil, errs.NewSize("invalid number of statements")
	}
	if len(witness) != len(p) {
		return nil, nil, errs.NewSize("invalid number of witnesses")
	}
	a := make(Commitment[A], len(p))
	s := make(State[S], len(p))
	var eg errgroup.Group
	for i, sigmai := range p {
		eg.Go(func() error {
			var err error
			a[i], s[i], err = sigmai.ComputeProverCommitment(statement[i], witness[i])
			if err != nil {
				return errs.WrapFailed(err, "failed to compute prover commitment")
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute commitments")
	}
	return a, s, nil
}

func (p protocol[X, W, A, S, Z]) ComputeProverResponse(statement Statement[X], witness Witness[W], commitment Commitment[A], state State[S], challengeBytes sigma.ChallengeBytes) (Response[Z], error) {
	if len(statement) != len(p) {
		return nil, errs.NewSize("invalid number of statements")
	}
	if len(witness) != len(p) {
		return nil, errs.NewSize("invalid number of witnesses")
	}
	if len(commitment) != len(p) {
		return nil, errs.NewSize("invalid number of commitments")
	}
	if len(state) != len(p) {
		return nil, errs.NewSize("invalid number of states")
	}
	z := make(Response[Z], len(p))
	var eg errgroup.Group
	for i, sigmai := range p {
		eg.Go(func() error {
			var err error
			z[i], err = sigmai.ComputeProverResponse(statement[i], witness[i], commitment[i], state[i], challengeBytes)
			if err != nil {
				return errs.WrapFailed(err, "failed to compute prover response")
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, errs.WrapFailed(err, "cannot compute responses")
	}
	return z, nil
}

func (p protocol[X, W, A, S, Z]) Verify(statement Statement[X], commitment Commitment[A], challengeBytes sigma.ChallengeBytes, response Response[Z]) error {
	if len(statement) != len(p) {
		return errs.NewSize("invalid number of statements")
	}
	if len(commitment) != len(p) {
		return errs.NewSize("invalid number of commitments")
	}
	if len(response) != len(p) {
		return errs.NewSize("invalid number of responses")
	}
	var eg errgroup.Group
	for i, sigmai := range p {
		eg.Go(func() error {
			return sigmai.Verify(statement[i], commitment[i], challengeBytes, response[i])
		})
	}
	if err := eg.Wait(); err != nil {
		return errs.WrapVerification(err, "verification failed")
	}
	return nil
}

func (p protocol[X, W, A, S, Z]) RunSimulator(statement Statement[X], challengeBytes sigma.ChallengeBytes) (Commitment[A], Response[Z], error) {
	if len(statement) != len(p) {
		return nil, nil, errs.NewSize("invalid number of statements")
	}
	a := make(Commitment[A], len(p))
	s := make(Response[Z], len(p))
	var eg errgroup.Group
	for i, sigmai := range p {
		eg.Go(func() error {
			var err error
			a[i], s[i], err = sigmai.RunSimulator(statement[i], challengeBytes)
			if err != nil {
				return errs.WrapFailed(err, "failed to run simulator")
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run simulator")
	}
	return a, s, nil
}

func (p protocol[X, W, A, S, Z]) SpecialSoundness() uint {
	return p[0].SpecialSoundness()
}

func (p protocol[X, W, A, S, Z]) GetChallengeBytesLength() int {
	return p[0].GetChallengeBytesLength()
}

func (p protocol[X, W, A, S, Z]) SoundnessError() uint {
	return p[0].SoundnessError()
}

func (p protocol[X, W, A, S, Z]) ValidateStatement(statement Statement[X], witness Witness[W]) error {
	if len(statement) != len(p) {
		return errs.NewSize("invalid number of statements")
	}
	if len(witness) != len(p) {
		return errs.NewSize("invalid number of witnesses")
	}
	for i := range p {
		if err := p[i].ValidateStatement(statement[i], witness[i]); err != nil {
			return errs.WrapArgument(err, "invalid statement/witness at index %d", i)
		}
	}
	return nil
}

func (p protocol[X, W, A, S, Z]) Name() sigma.Name {
	return sigma.Name(fmt.Sprintf("(%s)^%d", p[0].Name(), len(p)))
}
