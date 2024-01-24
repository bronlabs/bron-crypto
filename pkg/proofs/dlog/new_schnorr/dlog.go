package new_schnorr

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

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

type schnorr struct {
	base  curves.Point
	curve curves.Curve
	prng  io.Reader
}

var _ sigma.Protocol[Statement, Witness, Commitment, State, Response] = (*schnorr)(nil)

func NewSigmaProtocol(base curves.Point, prng io.Reader) (sigma.Protocol[Statement, Witness, Commitment, State, Response], error) {
	if base == nil {
		return nil, errs.NewIsNil("base")
	}
	if prng == nil {
		prng = crand.Reader
	}

	return &schnorr{
		base:  base,
		curve: base.Curve(),
		prng:  prng,
	}, nil
}

func (s *schnorr) ComputeProverCommitment(_ Statement, _ Witness) (Commitment, State, error) {
	k, err := s.curve.ScalarField().Random(s.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "cannot sample scalar")
	}
	r := s.base.Mul(k)

	return r, k, nil
}

func (s *schnorr) ComputeProverResponse(_ Statement, witness Witness, _ Commitment, state State, challengeBytes []byte) (Response, error) {
	if witness == nil || witness.ScalarField().Curve().Name() != s.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}
	if state == nil || state.ScalarField().Curve().Name() != s.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}
	if len(challengeBytes) != s.GetChallengeBytesLength() {
		return nil, errs.NewIsNil("invalid challenge bytes length")
	}
	e, err := s.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "cannot hash to scalar")
	}

	z := state.Add(witness.Mul(e))
	return z, nil
}

func (s *schnorr) Verify(statement Statement, commitment Commitment, challengeBytes []byte, response Response) error {
	if statement == nil || commitment == nil || challengeBytes == nil || response == nil {
		return errs.NewIsNil("passed nil")
	}
	if statement.Curve().Name() != s.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}
	if commitment.Curve().Name() != s.curve.Name() || response.ScalarField().Curve().Name() != s.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}
	if len(challengeBytes) != s.GetChallengeBytesLength() {
		return errs.NewInvalidArgument("invalid challenge bytes length")
	}
	e, err := s.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return errs.WrapInvalidArgument(err, "cannot hash to scalar")
	}

	left := s.base.Mul(response)
	right := statement.Mul(e).Add(commitment)
	if !left.Equal(right) {
		return errs.NewVerificationFailed("verification failed")
	}

	return nil
}

func (s *schnorr) RunSimulator(statement Statement, challengeBytes []byte) (Commitment, Response, error) {
	if statement == nil || statement.Curve().Name() != s.curve.Name() {
		return nil, nil, errs.NewInvalidArgument("statement")
	}
	if len(challengeBytes) != s.GetChallengeBytesLength() {
		return nil, nil, errs.NewInvalidArgument("invalid challenge bytes length")
	}

	e, err := s.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, nil, err
	}

	z, err := s.curve.ScalarField().Random(s.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "cannot sample scalar")
	}

	a := s.base.Mul(z).Sub(statement.Mul(e))
	return a, z, nil
}

func (s *schnorr) ValidateStatement(statement Statement, witness Witness) error {
	if statement == nil ||
		witness == nil ||
		statement.Curve().Name() != witness.ScalarField().Curve().Name() ||
		!s.base.Mul(witness).Equal(statement) {

		return errs.NewInvalidArgument("invalid statement")
	}

	return nil
}

func (s *schnorr) GetChallengeBytesLength() int {
	return s.curve.ScalarField().WideFieldBytes()
}

func (*schnorr) DomainSeparationLabel() string {
	return "ZKPOK_DLOG_SCHNORR"
}

func (*schnorr) SerializeStatement(statement Statement) []byte {
	return statement.ToAffineCompressed()
}

func (*schnorr) SerializeCommitment(commitment Commitment) []byte {
	return commitment.ToAffineCompressed()
}

func (*schnorr) SerializeResponse(response Response) []byte {
	return response.Bytes()
}

func (s *schnorr) mapChallengeBytesToChallenge(challengeBytes []byte) (curves.Scalar, error) {
	e, err := s.curve.ScalarField().Zero().SetBytesWide(challengeBytes)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "cannot hash to scalar")
	}

	return e, nil
}
