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

type State[S sigma.State, Z sigma.Response] struct {
	B uint
	S []S
	E []byte
	Z []Z
}

var _ sigma.State = (*State[sigma.State, sigma.Response])(nil)

type Response[Z sigma.Response] struct {
	E [][]byte
	Z []Z
}

func (r Response[Z]) Bytes() []byte {
	return sliceutils.Fold(func(acc []byte, x Z) []byte { return slices.Concat(acc, x.Bytes()) },
		binary.BigEndian.AppendUint64(nil, uint64(len(r.Z))),
		r.Z...,
	)
}

var _ sigma.Response = (*Response[sigma.Response])(nil)

func ComposeStatements[X sigma.Statement](statements ...X) Statement[X] {
	return statements
}

func ComposeWitnesses[W sigma.Witness](witnesses ...W) Witness[W] {
	return witnesses
}

type protocol[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sigmas []sigma.Protocol[X, W, A, S, Z]
	prng   io.Reader
}

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

func (p *protocol[X, W, A, S, Z]) SoundnessError() uint {
	return p.sigmas[0].SoundnessError()
}

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
		Z: make([]Z, len(p.sigmas)),
	}

	s.E = make([]byte, p.GetChallengeBytesLength())
	_, err := io.ReadFull(p.prng, s.E)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	s.B, err = p.getB(statement, witness)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot determine valid statement index")
	}

	var eg errgroup.Group
	for i, sigmai := range p.sigmas {
		if i == int(s.B) {
			eg.Go(func() error {
				var err error
				a[i], s.S[i], err = sigmai.ComputeProverCommitment(statement[i], witness[i])
				if err != nil {
					return errs2.Wrap(err)
				}
				return nil
			})
		} else {
			eg.Go(func() error {
				var err error
				a[i], s.Z[i], err = sigmai.RunSimulator(statement[i], s.E[:sigmai.GetChallengeBytesLength()])
				if err != nil {
					return errs2.Wrap(err)
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
	if len(state.S) != len(p.sigmas) || len(state.Z) != len(p.sigmas) {
		return nil, ErrInvalidLength.WithMessage("invalid state length")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, ErrInvalidLength.WithMessage("invalid challenge length")
	}

	z := &Response[Z]{
		E: make([][]byte, len(p.sigmas)),
		Z: make([]Z, len(p.sigmas)),
	}

	var err error
	for i, sigmai := range p.sigmas {
		if i == int(state.B) {
			z.E[i] = make([]byte, p.GetChallengeBytesLength())
			subtle.XORBytes(z.E[i], state.E, challenge)
			z.Z[i], err = sigmai.ComputeProverResponse(statement[i], witness[i], commitment[i], state.S[i], z.E[i][:sigmai.GetChallengeBytesLength()])
			if err != nil {
				return nil, errs2.Wrap(err)
			}
		} else {
			z.E[i] = state.E
			z.Z[i] = state.Z[i]
		}
	}
	return z, nil
}

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
			_, err := io.ReadFull(p.prng, z.E[0])
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot sample challenges")
	}
	z.E[len(p.sigmas)-1] = make([]byte, p.GetChallengeBytesLength())
	subtle.XORBytes(z.E[len(p.sigmas)-1], z.E[0], z.E[1])
	for i := 2; i < len(p.sigmas)-1; i++ {
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

func (p *protocol[X, W, A, S, Z]) SpecialSoundness() uint {
	return p.sigmas[0].SpecialSoundness()
}

func (p *protocol[X, W, A, S, Z]) GetChallengeBytesLength() int {
	return p.sigmas[0].GetChallengeBytesLength()
}

func (p *protocol[X, W, A, S, Z]) ValidateStatement(statement Statement[X], witness Witness[W]) error {
	if len(statement) != len(p.sigmas) {
		return ErrInvalidLength.WithMessage("invalid statement length")
	}
	if len(witness) != len(p.sigmas) {
		return ErrInvalidLength.WithMessage("invalid witness length")
	}
	errors := []error{}
	for i, sigmai := range p.sigmas {
		if invalid := sigmai.ValidateStatement(statement[i], witness[i]); invalid != nil {
			errors = append(errors, errs2.Wrap(invalid).WithMessage("statement/witness %d is invalid", i))
		}
	}
	if len(errors) > 0 {
		return errs2.Join(errors...).WithMessage("statement/witness validation failed")
	}
	return nil
}

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

func (p *protocol[X, W, A, S, Z]) Name() sigma.Name {
	return sigma.Name(fmt.Sprintf("SigmaOR(%s)^%d", p.sigmas[0].Name(), len(p.sigmas)))
}

var (
	ErrIsNil               = errs2.New("is nil")
	ErrNotExactlyOneOutOfN = errs2.New("not exactly one statement out of n is valid")
	ErrInvalidLength       = errs2.New("invalid length")
	ErrInvalidArgument     = errs2.New("invalid argument")
	ErrVerification        = errs2.New("verification failed")
)
