package batch_schnorr

import (
	crand "crypto/rand"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
)

const Name sigma.Name = "ZKPOK_BATCH_DLOG_SCHNORR"

type Statement []curves.Point

var _ sigma.Statement = Statement(nil)

type Witness []curves.Scalar

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
		return nil, errs.NewIsNil("base is nil")
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

func (b *protocol) SoundnessError() int {
	return b.curve.ScalarField().Order().BitLen()
}

func (b *protocol) ComputeProverCommitment(_ Statement, _ Witness) (Commitment, State, error) {
	k, err := b.curve.ScalarField().Random(b.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "random scalar failed")
	}

	r := b.base.ScalarMul(k)
	return r, k, nil
}

func (b *protocol) ComputeProverResponse(_ Statement, witness Witness, _ Commitment, state State, challengeBytes sigma.ChallengeBytes) (Response, error) {
	for _, w := range witness {
		if w.ScalarField().Curve().Name() != b.curve.Name() {
			return nil, errs.NewArgument("invalid curve")
		}
	}
	if state.ScalarField().Curve().Name() != b.curve.Name() {
		return nil, errs.NewArgument("invalid curve")
	}
	if len(challengeBytes) != b.GetChallengeBytesLength() {
		return nil, errs.NewArgument("invalid challenge bytes length")
	}
	e, err := b.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, errs.WrapArgument(err, "cannot hash to scalar")
	}

	coefficients := make([]curves.Scalar, len(witness)+1)
	copy(coefficients, witness)
	coefficients[len(witness)] = state
	z := evalPolyAt(e, coefficients)
	return z, nil
}

func (b *protocol) Verify(statement Statement, commitment Commitment, challengeBytes sigma.ChallengeBytes, response Response) error {
	if len(statement) == 0 || commitment == nil || challengeBytes == nil || response == nil {
		return errs.NewIsNil("passed nil")
	}
	for _, x := range statement {
		if x.Curve().Name() != b.curve.Name() {
			return errs.NewArgument("invalid curve")
		}
	}
	if commitment.Curve().Name() != b.curve.Name() || response.ScalarField().Curve().Name() != b.curve.Name() {
		return errs.NewArgument("invalid curve")
	}
	if len(challengeBytes) != b.GetChallengeBytesLength() {
		return errs.NewArgument("empty challenge")
	}
	e, err := b.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return errs.WrapArgument(err, "cannot hash to scalar")
	}

	coefficients := make([]curves.Point, len(statement)+1)
	copy(coefficients, statement)
	coefficients[len(statement)] = b.base.ScalarMul(response).Neg()
	z := evalPolyInExponentAt(e, coefficients)
	if !commitment.Neg().Equal(z) {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (b *protocol) RunSimulator(statement Statement, challengeBytes sigma.ChallengeBytes) (Commitment, Response, error) {
	if statement == nil {
		return nil, nil, errs.NewIsNil("statement")
	}
	for _, s := range statement {
		if s.Curve().Name() != b.curve.Name() {
			return nil, nil, errs.NewArgument("invalid curve")
		}
	}
	if len(challengeBytes) != b.GetChallengeBytesLength() {
		return nil, nil, errs.NewArgument("invalid challenge bytes length")
	}

	e, err := b.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot map challenge bytes to scalar")
	}

	z, err := b.curve.ScalarField().Random(b.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}

	coefficients := make([]curves.Point, len(statement)+1)
	copy(coefficients, statement)
	coefficients[len(statement)] = b.curve.AdditiveIdentity()

	a := b.base.ScalarMul(z).Sub(evalPolyInExponentAt(e, coefficients))

	return a, z, nil
}

func (b *protocol) ValidateStatement(statement Statement, witness Witness) error {
	if len(statement) == 0 || len(statement) != len(witness) {
		return errs.NewArgument("invalid statement")
	}

	for i, s := range statement {
		if !b.base.ScalarMul(witness[i]).Equal(s) {
			return errs.NewArgument("invalid statement")
		}
	}

	return nil
}

func (b *protocol) GetChallengeBytesLength() int {
	return b.curve.ScalarField().WideElementSize()
}

func (*protocol) SerializeStatement(statement Statement) []byte {
	result := make([]byte, 0)
	for _, p := range statement {
		result = append(result, p.ToAffineCompressed()...)
	}
	return result
}

func (*protocol) SerializeCommitment(commitment Commitment) []byte {
	return commitment.ToAffineCompressed()
}

func (*protocol) SerializeResponse(response Response) []byte {
	return response.Bytes()
}

func (b *protocol) mapChallengeBytesToChallenge(challengeBytes []byte) (curves.Scalar, error) {
	e, err := b.curve.ScalarField().Zero().SetBytesWide(challengeBytes)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash to scalar")
	}

	return e, nil
}

func (*protocol) Name() sigma.Name {
	return Name
}

func evalPolyAt(at curves.Scalar, coefficients []curves.Scalar) curves.Scalar {
	s := at.ScalarField().Zero()
	for _, coefficient := range coefficients {
		s = s.Mul(at).Add(coefficient)
	}

	return s
}

func evalPolyInExponentAt(at curves.Scalar, coefficients []curves.Point) curves.Point {
	s := coefficients[0].Curve().AdditiveIdentity()
	for _, c := range coefficients {
		s = s.ScalarMul(at).Add(c)
	}

	return s
}
