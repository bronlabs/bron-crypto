package new_schnorr

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

type schnorr struct {
	base  curves.Point
	curve curves.Curve
	prng  io.Reader
}

var _ sigma.Protocol[curves.Point, curves.Scalar, curves.Point, curves.Scalar, curves.Scalar, curves.Scalar] = (*schnorr)(nil)

func NewSigmaProtocol(base curves.Point, prng io.Reader) (sigma.Protocol[curves.Point, curves.Scalar, curves.Point, curves.Scalar, curves.Scalar, curves.Scalar], error) {
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

func (s *schnorr) GenerateCommitment(statement curves.Point, witness curves.Scalar) (curves.Point, curves.Scalar, error) {
	if statement == nil || witness == nil {
		return nil, nil, errs.NewInvalidArgument("statement/witness is")
	}
	if witness.ScalarField().Curve().Name() != s.curve.Name() || statement.Curve().Name() != s.curve.Name() {
		return nil, nil, errs.NewInvalidArgument("curve mismatch between statement and witness")
	}
	if !s.base.Mul(witness).Equal(statement) {
		return nil, nil, errs.NewInvalidArgument("statement/witness mismatch")
	}

	k, err := s.curve.ScalarField().Random(s.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "cannot sample scalar")
	}
	r := s.base.Mul(k)

	return r, k, nil
}

func (s *schnorr) GenerateChallenge(entropy []byte) (curves.Scalar, error) {
	if len(entropy) == 0 {
		return nil, errs.NewInvalidArgument("entropy is empty")
	}

	c, err := s.curve.ScalarField().Hash(entropy)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "cannot hash to scalar")
	}

	return c, nil
}

func (s *schnorr) GenerateResponse(_ curves.Point, witness, state, challenge curves.Scalar) (curves.Scalar, error) {
	if witness == nil || witness.ScalarField().Curve().Name() != s.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}
	if state == nil || state.ScalarField().Curve().Name() != s.curve.Name() || challenge == nil || challenge.ScalarField().Curve().Name() != s.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}

	z := state.Add(witness.Mul(challenge))
	return z, nil
}

func (s *schnorr) Verify(statement, commitment curves.Point, challenge, response curves.Scalar) error {
	if statement == nil || commitment == nil || challenge == nil || response == nil {
		return errs.NewIsNil("passed nil")
	}
	if statement.Curve().Name() != s.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}
	if commitment.Curve().Name() != s.curve.Name() || challenge.ScalarField().Curve().Name() != s.curve.Name() || response.ScalarField().Curve().Name() != s.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}

	left := s.base.Mul(response)
	right := statement.Mul(challenge).Add(commitment)
	if !left.Equal(right) {
		return errs.NewVerificationFailed("verification failed")
	}

	return nil
}

func (*schnorr) DomainSeparationLabel() string {
	return "ZKPOK_DLOG_SCHNORR"
}

func (*schnorr) SerializeStatement(statement curves.Point) []byte {
	return statement.ToAffineCompressed()
}

func (*schnorr) SerializeCommitment(commitment curves.Point) []byte {
	return commitment.ToAffineCompressed()
}

func (*schnorr) SerializeChallenge(challenge curves.Scalar) []byte {
	return challenge.Bytes()
}

func (*schnorr) SerializeResponse(response curves.Scalar) []byte {
	return response.Bytes()
}
