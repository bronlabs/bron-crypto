package new_chaum

import (
	"bytes"
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

type Statement struct {
	X1 curves.Point
	X2 curves.Point

	_ types.Incomparable
}

type Commitment struct {
	A1 curves.Point
	A2 curves.Point
}

type chaum struct {
	g1    curves.Point
	g2    curves.Point
	curve curves.Curve
	prng  io.Reader
}

var _ sigma.Protocol[*Statement, curves.Scalar, *Commitment, curves.Scalar, curves.Scalar, curves.Scalar] = (*chaum)(nil)

func NewSigmaProtocol(g1, g2 curves.Point, prng io.Reader) (sigma.Protocol[*Statement, curves.Scalar, *Commitment, curves.Scalar, curves.Scalar, curves.Scalar], error) {
	if g1 == nil || g2 == nil {
		return nil, errs.NewIsNil("g1 or g2 is nil")
	}
	if g1.Curve().Name() != g2.Curve().Name() {
		return nil, errs.NewInvalidArgument("g1 and g2 are on different curves")
	}
	if prng == nil {
		prng = crand.Reader
	}

	return &chaum{
		g1:    g1,
		g2:    g2,
		curve: g1.Curve(),
		prng:  prng,
	}, nil
}

func (c *chaum) GenerateCommitment(statement *Statement, witness curves.Scalar) (*Commitment, curves.Scalar, error) {
	if statement == nil || statement.X1 == nil || statement.X2 == nil || witness == nil {
		return nil, nil, errs.NewIsNil("witness or statement")
	}
	if !c.g1.Mul(witness).Equal(statement.X1) || !c.g2.Mul(witness).Equal(statement.X2) {
		return nil, nil, errs.NewInvalidArgument("invalid statement")
	}

	s, err := c.curve.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "cannot sample scalar")
	}

	a1 := c.g1.Mul(s)
	a2 := c.g2.Mul(s)

	return &Commitment{
		A1: a1,
		A2: a2,
	}, s, nil
}

func (c *chaum) GenerateChallenge(entropy []byte) (curves.Scalar, error) {
	if len(entropy) == 0 {
		return nil, errs.NewInvalidArgument("entropy is empty")
	}

	e, err := c.curve.ScalarField().Hash(entropy)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to scalar failed")
	}

	return e, nil
}

func (c *chaum) GenerateResponse(statement *Statement, witness, state, challenge curves.Scalar) (curves.Scalar, error) {
	if statement == nil || statement.X1 == nil || statement.X2 == nil || statement.X1.Curve().Name() != c.curve.Name() || statement.X2.Curve().Name() != c.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}
	if witness == nil || witness.ScalarField().Curve().Name() != c.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}
	if state == nil || state.ScalarField().Curve().Name() != c.curve.Name() || challenge == nil || challenge.ScalarField().Curve().Name() != c.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}
	if !c.g1.Mul(witness).Equal(statement.X1) || !c.g2.Mul(witness).Equal(statement.X2) {
		return nil, errs.NewInvalidArgument("invalid statement")
	}

	z := state.Add(witness.Mul(challenge))
	return z, nil
}

func (c *chaum) Verify(statement *Statement, commitment *Commitment, challenge, response curves.Scalar) error {
	if statement == nil || statement.X1 == nil || statement.X2 == nil || commitment == nil || challenge == nil || response == nil {
		return errs.NewIsNil("passed nil")
	}
	if statement.X1.Curve().Name() != c.curve.Name() || statement.X2.Curve().Name() != c.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}
	if commitment.A1.Curve().Name() != c.curve.Name() || commitment.A2.Curve().Name() != c.curve.Name() || challenge.ScalarField().Curve().Name() != c.curve.Name() || response.ScalarField().Curve().Name() != c.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}

	if !c.g1.Mul(response).Sub(statement.X1.Mul(challenge).Add(commitment.A1)).IsIdentity() {
		return errs.NewVerificationFailed("verification, failed")
	}
	if !c.g2.Mul(response).Sub(statement.X2.Mul(challenge).Add(commitment.A2)).IsIdentity() {
		return errs.NewVerificationFailed("verification, failed")
	}

	return nil
}

func (*chaum) DomainSeparationLabel() string {
	return "ZKPOK_DLEQ_CHAUM_PEDERSEN"
}

func (*chaum) SerializeStatement(statement *Statement) []byte {
	return bytes.Join([][]byte{statement.X1.ToAffineCompressed(), statement.X2.ToAffineCompressed()}, nil)
}

func (*chaum) SerializeCommitment(commitment *Commitment) []byte {
	return bytes.Join([][]byte{commitment.A1.ToAffineCompressed(), commitment.A2.ToAffineCompressed()}, nil)
}

func (*chaum) SerializeChallenge(challenge curves.Scalar) []byte {
	return challenge.Bytes()
}

func (*chaum) SerializeResponse(response curves.Scalar) []byte {
	return response.Bytes()
}
