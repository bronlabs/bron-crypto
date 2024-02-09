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

var _ sigma.Statement = (*Statement)(nil)

type Witness curves.Scalar

var _ sigma.Witness = Witness(nil)

type Commitment struct {
	A1 curves.Point
	A2 curves.Point
}

var _ sigma.Commitment = (*Commitment)(nil)

type State curves.Scalar

var _ sigma.State = State(nil)

type Response curves.Scalar

var _ sigma.Response = Response(nil)

type chaum struct {
	g1    curves.Point
	g2    curves.Point
	curve curves.Curve
	prng  io.Reader
}

var _ sigma.Protocol[*Statement, Witness, *Commitment, State, Response] = (*chaum)(nil)

func NewSigmaProtocol(g1, g2 curves.Point, prng io.Reader) (sigma.Protocol[*Statement, Witness, *Commitment, State, Response], error) {
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

func (c *chaum) ComputeProverCommitment(_ *Statement, _ Witness) (*Commitment, State, error) {
	s, err := c.curve.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "cannot sample scalar")
	}

	a1 := c.g1.ScalarMul(s)
	a2 := c.g2.ScalarMul(s)

	return &Commitment{
		A1: a1,
		A2: a2,
	}, s, nil
}

func (c *chaum) ComputeProverResponse(_ *Statement, witness Witness, _ *Commitment, state State, challengeBytes []byte) (Response, error) {
	if witness == nil || witness.ScalarField().Curve().Name() != c.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}
	if state == nil || state.ScalarField().Curve().Name() != c.curve.Name() {
		return nil, errs.NewInvalidArgument("invalid curve")
	}
	if len(challengeBytes) != c.GetChallengeBytesLength() {
		return nil, errs.NewInvalidArgument("invalid challenge bytes length")
	}
	e, err := c.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "cannot hash to scalar")
	}

	z := state.Add(witness.Mul(e))
	return z, nil
}

func (c *chaum) Verify(statement *Statement, commitment *Commitment, challengeBytes []byte, response Response) error {
	if statement == nil || statement.X1 == nil || statement.X2 == nil || commitment == nil || response == nil {
		return errs.NewIsNil("passed nil")
	}
	if statement.X1.Curve().Name() != c.curve.Name() || statement.X2.Curve().Name() != c.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}
	if commitment.A1.Curve().Name() != c.curve.Name() || commitment.A2.Curve().Name() != c.curve.Name() || response.ScalarField().Curve().Name() != c.curve.Name() {
		return errs.NewInvalidArgument("invalid curve")
	}
	if len(challengeBytes) != c.GetChallengeBytesLength() {
		return errs.NewInvalidArgument("invalid challenge bytes length")
	}
	e, err := c.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return errs.WrapInvalidArgument(err, "cannot hash to scalar")
	}

	if !c.g1.ScalarMul(response).Sub(statement.X1.ScalarMul(e).Add(commitment.A1)).IsIdentity() {
		return errs.NewVerificationFailed("verification, failed")
	}
	if !c.g2.ScalarMul(response).Sub(statement.X2.ScalarMul(e).Add(commitment.A2)).IsIdentity() {
		return errs.NewVerificationFailed("verification, failed")
	}

	return nil
}

func (c *chaum) RunSimulator(statement *Statement, challengeBytes []byte) (*Commitment, Response, error) {
	if statement == nil ||
		statement.X1 == nil || statement.X1.Curve().Name() != c.curve.Name() ||
		statement.X2 == nil || statement.X2.Curve().Name() != c.curve.Name() {

		return nil, nil, errs.NewInvalidArgument("statement")
	}
	if len(challengeBytes) == 0 {
		return nil, nil, errs.NewInvalidArgument("randomness is empty")
	}

	e, err := c.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, nil, err
	}

	z, err := c.g1.Curve().ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "cannot sample scalar")
	}

	a := &Commitment{
		A1: c.g1.ScalarMul(z).Sub(statement.X1.ScalarMul(e)),
		A2: c.g2.ScalarMul(z).Sub(statement.X2.ScalarMul(e)),
	}

	return a, z, nil
}

func (c *chaum) GetChallengeBytesLength() int {
	return c.curve.ScalarField().WideFieldBytes()
}
func (c *chaum) ValidateStatement(statement *Statement, witness Witness) error {
	if statement == nil || witness == nil ||
		!c.g1.ScalarMul(witness).Equal(statement.X1) ||
		!c.g2.ScalarMul(witness).Equal(statement.X2) {

		return errs.NewInvalidArgument("invalid statement")
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

func (*chaum) SerializeResponse(response Response) []byte {
	return response.Bytes()
}

func (c *chaum) mapChallengeBytesToChallenge(challengeBytes []byte) (curves.Scalar, error) {
	e, err := c.curve.ScalarField().Zero().SetBytesWide(challengeBytes)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "cannot hash to scalar")
	}

	return e, nil
}
