package batch_schnorr

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

type batchSchnorr struct {
	base  curves.Point
	curve curves.Curve
	prng  io.Reader
}

var _ sigma.Protocol[[]curves.Point, []curves.Scalar, curves.Point, curves.Scalar, curves.Scalar, curves.Scalar] = (*batchSchnorr)(nil)

func NewSigmaProtocol(base curves.Point, prng io.Reader) (sigma.Protocol[[]curves.Point, []curves.Scalar, curves.Point, curves.Scalar, curves.Scalar, curves.Scalar], error) {
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

func (b *batchSchnorr) GenerateCommitment(statement []curves.Point, witness []curves.Scalar) (curves.Point, curves.Scalar, error) {
	if len(statement) == 0 || len(witness) == 0 || len(statement) != len(witness) {
		return nil, nil, errs.NewInvalidArgument("length mismatch statement/witness or empty")
	}
	for i := range statement {
		x := witness[i]
		y := statement[i]
		if x.ScalarField().Curve().Name() != b.curve.Name() || y.Curve().Name() != b.curve.Name() {
			return nil, nil, errs.NewInvalidArgument("curve mismatch between statement and witness")
		}
		if !b.base.Mul(x).Equal(y) {
			return nil, nil, errs.NewInvalidArgument("statement/witness mismatch")
		}
	}

	k, err := b.curve.ScalarField().Random(b.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "random scalar failed")
	}

	r := b.base.Mul(k)
	return r, k, nil
}

func (b *batchSchnorr) GenerateChallenge(entropy []byte) (curves.Scalar, error) {
	if len(entropy) == 0 {
		return nil, errs.NewInvalidArgument("entropy is empty")
	}

	e, err := b.curve.ScalarField().Hash(entropy)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to scalar failed")
	}

	return e, nil
}

func (b *batchSchnorr) GenerateResponse(_ []curves.Point, witness []curves.Scalar, state, challenge curves.Scalar) (curves.Scalar, error) {
	for _, w := range witness {
		if w.ScalarField().Curve().Name() != b.curve.Name() {
			return nil, errs.NewInvalidArgument("invalid curve")
		}
	}
	if state.ScalarField().Curve().Name() != b.curve.Name() || challenge.ScalarField().Curve().Name() != b.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}

	coefficients := make([]curves.Scalar, len(witness)+1)
	copy(coefficients, witness)
	coefficients[len(witness)] = state
	z := evalPolyAt(challenge, coefficients)
	return z, nil
}

func (b *batchSchnorr) Verify(statement []curves.Point, commitment curves.Point, challenge, response curves.Scalar) error {
	if len(statement) == 0 || commitment == nil || challenge == nil || response == nil {
		return errs.NewIsNil("passed nil")
	}
	for _, x := range statement {
		if x.Curve().Name() != b.curve.Name() {
			return errs.NewInvalidArgument("invalid curve")
		}
	}
	if commitment.Curve().Name() != b.curve.Name() || challenge.ScalarField().Curve().Name() != b.curve.Name() || response.ScalarField().Curve().Name() != b.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}

	coefficients := make([]curves.Point, len(statement)+1)
	copy(coefficients, statement)
	coefficients[len(statement)] = b.base.Mul(response).Neg()
	z := evalPolyInExponentAt(challenge, coefficients)
	if !commitment.Neg().Equal(z) {
		return errs.NewVerificationFailed("verification failed")
	}

	return nil
}

func (*batchSchnorr) DomainSeparationLabel() string {
	return "ZKPOK_BATCH_DLOG_SCHNORR"
}

func (*batchSchnorr) SerializeStatement(statement []curves.Point) []byte {
	result := make([]byte, 0)
	for _, p := range statement {
		result = append(result, p.ToAffineCompressed()...)
	}
	return result
}

func (*batchSchnorr) SerializeCommitment(commitment curves.Point) []byte {
	return commitment.ToAffineCompressed()
}

func (*batchSchnorr) SerializeChallenge(challenge curves.Scalar) []byte {
	return challenge.Bytes()
}

func (*batchSchnorr) SerializeResponse(response curves.Scalar) []byte {
	return response.Bytes()
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
