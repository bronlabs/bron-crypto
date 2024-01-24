package batch_schnorr

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

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

type batchSchnorr struct {
	base  curves.Point
	curve curves.Curve
	prng  io.Reader
}

var _ sigma.Protocol[Statement, Witness, Commitment, State, Response] = (*batchSchnorr)(nil)

func NewSigmaProtocol(base curves.Point, prng io.Reader) (sigma.Protocol[Statement, Witness, Commitment, State, Response], error) {
	if base == nil {
		return nil, errs.NewIsNil("base is nil")
	}
	if prng == nil {
		prng = crand.Reader
	}

	return &batchSchnorr{
		base:  base,
		curve: base.Curve(),
		prng:  prng,
	}, nil
}

func (b *batchSchnorr) ComputeProverCommitment(_ Statement, _ Witness) (Commitment, State, error) {
	k, err := b.curve.ScalarField().Random(b.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "random scalar failed")
	}

	r := b.base.Mul(k)
	return r, k, nil
}

func (b *batchSchnorr) ComputeProverResponse(_ Statement, witness Witness, _ Commitment, state State, challengeBytes []byte) (Response, error) {
	for _, w := range witness {
		if w.ScalarField().Curve().Name() != b.curve.Name() {
			return nil, errs.NewInvalidArgument("invalid curve")
		}
	}
	if state.ScalarField().Curve().Name() != b.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}
	if len(challengeBytes) != b.GetChallengeBytesLength() {
		return nil, errs.NewInvalidArgument("invalid challenge bytes length")
	}
	e, err := b.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "cannot hash to scalar")
	}

	coefficients := make([]curves.Scalar, len(witness)+1)
	copy(coefficients, witness)
	coefficients[len(witness)] = state
	z := evalPolyAt(e, coefficients)
	return z, nil
}

func (b *batchSchnorr) Verify(statement Statement, commitment Commitment, challengeBytes []byte, response Response) error {
	if len(statement) == 0 || commitment == nil || challengeBytes == nil || response == nil {
		return errs.NewIsNil("passed nil")
	}
	for _, x := range statement {
		if x.Curve().Name() != b.curve.Name() {
			return errs.NewInvalidArgument("invalid curve")
		}
	}
	if commitment.Curve().Name() != b.curve.Name() || response.ScalarField().Curve().Name() != b.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}
	if len(challengeBytes) != b.GetChallengeBytesLength() {
		return errs.NewInvalidArgument("empty challenge")
	}
	e, err := b.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return errs.WrapInvalidArgument(err, "cannot hash to scalar")
	}

	coefficients := make([]curves.Point, len(statement)+1)
	copy(coefficients, statement)
	coefficients[len(statement)] = b.base.Mul(response).Neg()
	z := evalPolyInExponentAt(e, coefficients)
	if !commitment.Neg().Equal(z) {
		return errs.NewVerificationFailed("verification failed")
	}

	return nil
}

func (b *batchSchnorr) RunSimulator(statement Statement, challengeBytes []byte) (Commitment, Response, error) {
	if statement == nil {
		return nil, nil, errs.NewIsNil("statement")
	}
	for _, s := range statement {
		if s.Curve().Name() != b.curve.Name() {
			return nil, nil, errs.NewInvalidArgument("invalid curve")
		}
	}
	if len(challengeBytes) != b.GetChallengeBytesLength() {
		return nil, nil, errs.NewInvalidArgument("invalid challenge bytes length")
	}

	e, err := b.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot map challenge bytes to scalar")
	}

	z, err := b.curve.ScalarField().Random(b.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "cannot sample scalar")
	}

	coefficients := make([]curves.Point, len(statement)+1)
	copy(coefficients, statement)
	coefficients[len(statement)] = b.curve.Identity()

	a := b.base.Mul(z).Sub(evalPolyInExponentAt(e, coefficients))

	return a, z, nil
}

func (b *batchSchnorr) ValidateStatement(statement Statement, witness Witness) error {
	if len(statement) == 0 || len(statement) != len(witness) {
		return errs.NewInvalidArgument("invalid statement")
	}

	for i, s := range statement {
		if !b.base.Mul(witness[i]).Equal(s) {
			return errs.NewInvalidArgument("invalid statement")
		}
	}

	return nil
}

func (b *batchSchnorr) GetChallengeBytesLength() int {
	return b.curve.ScalarField().WideFieldBytes()
}

func (*batchSchnorr) DomainSeparationLabel() string {
	return "ZKPOK_BATCH_DLOG_SCHNORR"
}

func (*batchSchnorr) SerializeStatement(statement Statement) []byte {
	result := make([]byte, 0)
	for _, p := range statement {
		result = append(result, p.ToAffineCompressed()...)
	}
	return result
}

func (*batchSchnorr) SerializeCommitment(commitment Commitment) []byte {
	return commitment.ToAffineCompressed()
}

func (*batchSchnorr) SerializeResponse(response Response) []byte {
	return response.Bytes()
}

func (b *batchSchnorr) mapChallengeBytesToChallenge(challengeBytes []byte) (curves.Scalar, error) {
	e, err := b.curve.ScalarField().Zero().SetBytesWide(challengeBytes)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "cannot hash to scalar")
	}

	return e, nil
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
		s = s.Mul(at).Add(c)
	}

	return s
}
