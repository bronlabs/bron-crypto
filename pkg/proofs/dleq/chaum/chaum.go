package chaum

import (
	crand "crypto/rand"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "ZKPOK_DLEQ_CHAUM_PEDERSEN"

type Statement struct {
	X1 curves.Point
	X2 curves.Point

	_ ds.Incomparable
}

func (s *Statement) Validate() error {
	if s == nil {
		return errs.NewIsNil("statement")
	}
	if s.X1 == nil {
		return errs.NewIsNil("X1")
	}
	if s.X2 == nil {
		return errs.NewIsNil("X2")
	}
	if s.X1.IsAdditiveIdentity() {
		return errs.NewArgument("X1 is identity")
	}
	if s.X2.IsAdditiveIdentity() {
		return errs.NewArgument("X2 is identity")
	}
	return nil
}

var _ sigma.Statement = (*Statement)(nil)

type Witness curves.Scalar

var _ sigma.Witness = Witness(nil)

type Commitment struct {
	A1 curves.Point
	A2 curves.Point
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("commitment")
	}
	if c.A1 == nil {
		return errs.NewIsNil("A1")
	}
	if c.A2 == nil {
		return errs.NewIsNil("A2")
	}
	if c.A1.IsAdditiveIdentity() {
		return errs.NewArgument("A1 is identity")
	}
	if c.A2.IsAdditiveIdentity() {
		return errs.NewArgument("A2 is identity")
	}
	return nil
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

func (c *protocol) SoundnessError() int {
	return c.g1.Curve().ScalarField().Order().BitLen()
}

func (c *protocol) ComputeProverCommitment(_ *Statement, w Witness) (*Commitment, State, error) {
	s, err := w.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}

	a1 := c.g1.ScalarMul(s)
	a2 := c.g2.ScalarMul(s)

	return &Commitment{
		A1: a1,
		A2: a2,
	}, s, nil
}

func (c *protocol) ComputeProverResponse(_ *Statement, witness Witness, _ *Commitment, state State, challengeBytes sigma.ChallengeBytes) (Response, error) {
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

func (c *protocol) Verify(statement *Statement, commitment *Commitment, challengeBytes sigma.ChallengeBytes, response Response) error {
	if err := statement.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid statement")
	}
	if err := commitment.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid commitment")
	}
	if len(challengeBytes) != c.GetChallengeBytesLength() {
		return errs.NewLength("invalid challenge bytes length")
	}
	e, err := c.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return errs.WrapArgument(err, "cannot hash to scalar")
	}

	if !c.g1.ScalarMul(response).Sub(statement.X1.ScalarMul(e).Add(commitment.A1)).IsAdditiveIdentity() {
		return errs.NewVerification("verification, failed")
	}
	if !c.g2.ScalarMul(response).Sub(statement.X2.ScalarMul(e).Add(commitment.A2)).IsAdditiveIdentity() {
		return errs.NewVerification("verification, failed")
	}

	return nil
}

func (c *protocol) RunSimulator(statement *Statement, challengeBytes sigma.ChallengeBytes) (*Commitment, Response, error) {
	if err := statement.Validate(); err != nil {
		return nil, nil, errs.NewArgument("statement")
	}
	if len(challengeBytes) == 0 {
		return nil, nil, errs.NewArgument("randomness is empty")
	}

	e, err := c.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot map to scalar")
	}

	z, err := c.g1.Curve().ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}

	a := &Commitment{
		A1: c.g1.ScalarMul(z).Sub(statement.X1.ScalarMul(e)),
		A2: c.g2.ScalarMul(z).Sub(statement.X2.ScalarMul(e)),
	}

	return a, z, nil
}

func (*protocol) SpecialSoundness() uint {
	return 2
}

func (c *protocol) GetChallengeBytesLength() int {
	var biggerSubGroup curves.Curve
	gt, _, _ := c.g1.Curve().Order().Cmp(c.g2.Curve().Order())
	if gt == 1 {
		biggerSubGroup = c.g1.Curve()
	} else {
		biggerSubGroup = c.g2.Curve()
	}
	return biggerSubGroup.ScalarField().WideElementSize()
}
func (c *protocol) ValidateStatement(statement *Statement, witness Witness) (err error) {
	if err = statement.Validate(); err != nil || witness == nil ||
		!c.g1.ScalarMul(witness).Equal(statement.X1) ||
		!c.g2.ScalarMul(witness).Equal(statement.X2) {

		return errs.WrapArgument(err, "invalid statement")
	}

	return nil
}

func (*protocol) SerializeStatement(statement *Statement) []byte {
	return slices.Concat(statement.X1.ToAffineCompressed(), statement.X2.ToAffineCompressed())
}

func (*protocol) SerializeCommitment(commitment *Commitment) []byte {
	return slices.Concat(commitment.A1.ToAffineCompressed(), commitment.A2.ToAffineCompressed())
}

func (*protocol) SerializeResponse(response Response) []byte {
	return response.Bytes()
}

func (c *protocol) mapChallengeBytesToChallenge(challengeBytes sigma.ChallengeBytes) (curves.Scalar, error) {
	e, err := c.g1.Curve().ScalarField().Zero().SetBytesWide(challengeBytes)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash to scalar")
	}

	return e, nil
}

func (*protocol) Name() sigma.Name {
	return Name
}
