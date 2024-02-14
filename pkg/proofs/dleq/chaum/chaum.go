package chaum

import (
	"bytes"
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

const Name sigma.Name = "ZKPOK_DLEQ_CHAUM_PEDERSEN"

type Statement struct {
	X1 curves.Point
	X2 curves.Point

	_ ds.Incomparable
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

type protocol struct {
	g1   curves.Point
	g2   curves.Point
	prng io.Reader
}

var _ sigma.Protocol[*Statement, Witness, *Commitment, State, Response] = (*protocol)(nil)

func NewSigmaProtocol(g1, g2 curves.Point, prng io.Reader) (sigma.Protocol[*Statement, Witness, *Commitment, State, Response], error) {
	if g1 == nil || g2 == nil {
		return nil, errs.NewIsNil("g1 or g2 is nil")
	}
	if prng == nil {
		prng = crand.Reader
	}

	return &protocol{
		g1:   g1,
		g2:   g2,
		prng: prng,
	}, nil
}

func (c *protocol) ComputeProverCommitment(_ *Statement, w Witness) (*Commitment, State, error) {
	s, err := w.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}

	a1 := c.g1.Mul(s)
	a2 := c.g2.Mul(s)

	return &Commitment{
		A1: a1,
		A2: a2,
	}, s, nil
}

func (c *protocol) ComputeProverResponse(_ *Statement, witness Witness, _ *Commitment, state State, challengeBytes []byte) (Response, error) {
	if len(challengeBytes) != c.GetChallengeBytesLength() {
		return nil, errs.NewArgument("invalid challenge bytes length")
	}
	e, err := c.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, errs.WrapArgument(err, "cannot hash to scalar")
	}

	z := state.Add(witness.Mul(e))
	return z, nil
}

func (c *protocol) Verify(statement *Statement, commitment *Commitment, challengeBytes []byte, response Response) error {
	if statement == nil || statement.X1 == nil || statement.X2 == nil || commitment == nil || response == nil {
		return errs.NewIsNil("passed nil")
	}
	if len(challengeBytes) != c.GetChallengeBytesLength() {
		return errs.NewArgument("invalid challenge bytes length")
	}
	e, err := c.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return errs.WrapArgument(err, "cannot hash to scalar")
	}

	if !c.g1.Mul(response).Sub(statement.X1.Mul(e).Add(commitment.A1)).IsIdentity() {
		return errs.NewVerification("verification, failed")
	}
	if !c.g2.Mul(response).Sub(statement.X2.Mul(e).Add(commitment.A2)).IsIdentity() {
		return errs.NewVerification("verification, failed")
	}

	return nil
}

func (c *protocol) RunSimulator(statement *Statement, challengeBytes []byte) (*Commitment, Response, error) {
	if statement == nil {
		return nil, nil, errs.NewArgument("statement")
	}
	if len(challengeBytes) == 0 {
		return nil, nil, errs.NewArgument("randomness is empty")
	}

	e, err := c.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, nil, err
	}

	z, err := c.g1.Curve().ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}

	a := &Commitment{
		A1: c.g1.Mul(z).Sub(statement.X1.Mul(e)),
		A2: c.g2.Mul(z).Sub(statement.X2.Mul(e)),
	}

	return a, z, nil
}

func (c *protocol) GetChallengeBytesLength() int {
	var biggerSubGroup curves.Curve
	gt, _, _ := c.g1.Curve().Order().Cmp(c.g2.Curve().Order())
	if gt == 1 {
		biggerSubGroup = c.g1.Curve()
	} else {
		biggerSubGroup = c.g2.Curve()
	}
	return biggerSubGroup.ScalarField().WideFieldBytes()
}
func (c *protocol) ValidateStatement(statement *Statement, witness Witness) error {
	if statement == nil || witness == nil ||
		!c.g1.Mul(witness).Equal(statement.X1) ||
		!c.g2.Mul(witness).Equal(statement.X2) {

		return errs.NewArgument("invalid statement")
	}

	return nil
}

func (*protocol) SerializeStatement(statement *Statement) []byte {
	return bytes.Join([][]byte{statement.X1.ToAffineCompressed(), statement.X2.ToAffineCompressed()}, nil)
}

func (*protocol) SerializeCommitment(commitment *Commitment) []byte {
	return bytes.Join([][]byte{commitment.A1.ToAffineCompressed(), commitment.A2.ToAffineCompressed()}, nil)
}

func (*protocol) SerializeResponse(response Response) []byte {
	return response.Bytes()
}

func (c *protocol) mapChallengeBytesToChallenge(challengeBytes []byte) (curves.Scalar, error) {
	e, err := c.g1.Curve().ScalarField().Zero().SetBytesWide(challengeBytes)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash to scalar")
	}

	return e, nil
}

func (*protocol) Name() sigma.Name {
	return Name
}
