package schnorr

import (
	crand "crypto/rand"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "ZKPOK_DLOG_SCHNORR"

type Statement curves.Point

var _ sigma.Statement = Statement(nil)

type Witness curves.Scalar

var _ sigma.Witness = Witness(nil)

type Commitment curves.Point

var _ sigma.Commitment = Commitment(nil)

type State curves.Scalar

var _ sigma.State = State(nil)

type Response curves.Scalar

var _ sigma.Response = Response(nil)

type protocol struct {
	base  curves.Point
	curve curves.Curve
	prng  io.Reader
}

var _ sigma.Protocol[Statement, Witness, Commitment, State, Response] = (*protocol)(nil)

func NewSigmaProtocol(base curves.Point, prng io.Reader) (sigma.Protocol[Statement, Witness, Commitment, State, Response], error) {
	if base == nil {
		return nil, errs.NewIsNil("base")
	}
	if prng == nil {
		prng = crand.Reader
	}

	return &protocol{
		base:  base,
		curve: base.Curve(),
		prng:  prng,
	}, nil
}

func (s *protocol) SoundnessError() int {
	return s.curve.ScalarField().Order().BitLen()
}

func (s *protocol) ComputeProverCommitment(_ Statement, _ Witness) (Commitment, State, error) {
	k, err := s.curve.ScalarField().Random(s.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}
	r := s.base.ScalarMul(k)

	return r, k, nil
}

func (s *protocol) ComputeProverResponse(_ Statement, witness Witness, _ Commitment, state State, challengeBytes sigma.ChallengeBytes) (Response, error) {
	if witness == nil || witness.ScalarField().Curve().Name() != s.curve.Name() {
		return nil, errs.NewArgument("invalid curve")
	}
	if state == nil || state.ScalarField().Curve().Name() != s.curve.Name() {
		return nil, errs.NewArgument("invalid curve")
	}
	if len(challengeBytes) != s.GetChallengeBytesLength() {
		return nil, errs.NewIsNil("invalid challenge bytes length")
	}
	e, err := s.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, errs.WrapArgument(err, "cannot hash to scalar")
	}

	z := state.Add(witness.Mul(e))
	return z, nil
}

func (s *protocol) Verify(statement Statement, commitment Commitment, challengeBytes sigma.ChallengeBytes, response Response) error {
	if statement == nil || commitment == nil || challengeBytes == nil || response == nil {
		return errs.NewIsNil("passed nil")
	}
	if statement.Curve().Name() != s.curve.Name() {
		return errs.NewArgument("invalid curve")
	}
	if commitment.Curve().Name() != s.curve.Name() || response.ScalarField().Curve().Name() != s.curve.Name() {
		return errs.NewArgument("invalid curve")
	}
	if len(challengeBytes) != s.GetChallengeBytesLength() {
		return errs.NewArgument("invalid challenge bytes length")
	}
	e, err := s.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return errs.WrapArgument(err, "cannot hash to scalar")
	}

	left := s.base.ScalarMul(response)
	right := statement.ScalarMul(e).Add(commitment)
	if !left.Equal(right) {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (s *protocol) RunSimulator(statement Statement, challengeBytes sigma.ChallengeBytes) (Commitment, Response, error) {
	if statement == nil || statement.Curve().Name() != s.curve.Name() {
		return nil, nil, errs.NewArgument("statement")
	}
	if len(challengeBytes) != s.GetChallengeBytesLength() {
		return nil, nil, errs.NewArgument("invalid challenge bytes length")
	}

	e, err := s.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot map to scalar")
	}

	z, err := s.curve.ScalarField().Random(s.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}

	a := s.base.ScalarMul(z).Sub(statement.ScalarMul(e))
	return a, z, nil
}

func (*protocol) SpecialSoundness() uint {
	return 2
}

func (s *protocol) ValidateStatement(statement Statement, witness Witness) error {
	if statement == nil ||
		witness == nil ||
		statement.Curve().Name() != witness.ScalarField().Curve().Name() ||
		!s.base.ScalarMul(witness).Equal(statement) {

		return errs.NewArgument("invalid statement")
	}

	return nil
}

func (s *protocol) GetChallengeBytesLength() int {
	return s.curve.ScalarField().WideElementSize()
}

func (*protocol) SerializeStatement(statement Statement) []byte {
	return statement.ToAffineCompressed()
}

func (*protocol) SerializeCommitment(commitment Commitment) []byte {
	return commitment.ToAffineCompressed()
}

func (*protocol) SerializeResponse(response Response) []byte {
	return response.Bytes()
}

func (s *protocol) mapChallengeBytesToChallenge(challengeBytes []byte) (curves.Scalar, error) {
	e, err := s.curve.ScalarField().Zero().SetBytesWide(challengeBytes)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash to scalar")
	}

	return e, nil
}

func (*protocol) Name() sigma.Name {
	return Name
}
