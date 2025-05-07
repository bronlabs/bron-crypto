package schnorr

import (
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "ZKPOK_DLOG_SCHNORR"

type Statement[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	X P
}

func NewStatement[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](x P) *Statement[P, F, S] {
	return &Statement[P, F, S]{X: x}
}

type Witness[S fields.PrimeFieldElement[S]] struct {
	W S
}

func NewWitness[S fields.PrimeFieldElement[S]](w S) *Witness[S] {
	return &Witness[S]{W: w}
}

type Commitment[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	A P
}

func NewCommitment[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](a P) *Commitment[P, F, S] {
	return &Commitment[P, F, S]{A: a}
}

type State[S fields.PrimeFieldElement[S]] struct {
	S S
}

func NewState[S fields.PrimeFieldElement[S]](s S) *State[S] {
	return &State[S]{S: s}
}

type Response[S fields.PrimeFieldElement[S]] struct {
	Z S
}

func NewResponse[S fields.PrimeFieldElement[S]](z S) *Response[S] {
	return &Response[S]{Z: z}
}

type protocol[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	base P
	prng io.Reader
}

//var _ sigma.Protocol[Statement, Witness, Commitment, State, Response] = (*protocol)(nil)

func NewSigmaProtocol[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](base P, prng io.Reader) (sigma.Protocol[*Statement[P, F, S], *Witness[S], *Commitment[P, F, S], *State[S], *Response[S]], error) {
	//if base == nil {
	//	return nil, errs.NewIsNil("base")
	//}
	if prng == nil {
		prng = crand.Reader
	}

	return &protocol[P, F, S]{
		base: base,
		prng: prng,
	}, nil
}

func (s *protocol[P, F, S]) SoundnessError() int {
	curve, err := curves.GetCurve(s.base)
	if err != nil {
		panic(err)
	}

	return curve.ScalarField().Order().TrueLen()
}

func (s *protocol[P, F, S]) ComputeProverCommitment(_ *Statement[P, F, S], _ *Witness[S]) (*Commitment[P, F, S], *State[S], error) {
	curve, err := curves.GetCurve(s.base)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot get curve")
	}

	k, err := curve.ScalarField().Random(s.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}
	a := s.base.ScalarMul(k)

	return NewCommitment(a), NewState(k), nil
}

func (s *protocol[P, F, S]) ComputeProverResponse(_ *Statement[P, F, S], witness *Witness[S], _ *Commitment[P, F, S], state *State[S], challengeBytes sigma.ChallengeBytes) (*Response[S], error) {
	//if witness == nil || witness.ScalarField().Curve().Name() != s.curve.Name() {
	//	return nil, errs.NewArgument("invalid curve")
	//}
	//if state == nil || state.ScalarField().Curve().Name() != s.curve.Name() {
	//	return nil, errs.NewArgument("invalid curve")
	//}
	if len(challengeBytes) != s.GetChallengeBytesLength() {
		return nil, errs.NewIsNil("invalid challenge bytes length")
	}
	e, err := s.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, errs.WrapArgument(err, "cannot hash to scalar")
	}

	z := state.S.Add(witness.W.Mul(e))
	return NewResponse(z), nil
}

func (s *protocol[P, F, S]) Verify(statement *Statement[P, F, S], commitment *Commitment[P, F, S], challengeBytes sigma.ChallengeBytes, response *Response[S]) error {
	//if statement == nil || commitment == nil || challengeBytes == nil || response == nil {
	//	return errs.NewIsNil("passed nil")
	//}
	//if statement.Curve().Name() != s.curve.Name() {
	//	return errs.NewArgument("invalid curve")
	//}
	//if commitment.Curve().Name() != s.curve.Name() || response.ScalarField().Curve().Name() != s.curve.Name() {
	//	return errs.NewArgument("invalid curve")
	//}
	if len(challengeBytes) != s.GetChallengeBytesLength() {
		return errs.NewArgument("invalid challenge bytes length")
	}
	e, err := s.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return errs.WrapArgument(err, "cannot hash to scalar")
	}

	left := s.base.ScalarMul(response.Z)
	right := statement.X.ScalarMul(e).Op(commitment.A)
	if !left.Equal(right) {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (s *protocol[P, F, S]) RunSimulator(statement *Statement[P, F, S], challengeBytes sigma.ChallengeBytes) (*Commitment[P, F, S], *Response[S], error) {
	//if statement == nil || statement.Curve().Name() != s.curve.Name() {
	//	return nil, nil, errs.NewArgument("statement")
	//}
	if len(challengeBytes) != s.GetChallengeBytesLength() {
		return nil, nil, errs.NewArgument("invalid challenge bytes length")
	}

	e, err := s.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot map to scalar")
	}

	curve, err := curves.GetCurve(s.base)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot get curve")
	}
	z, err := curve.ScalarField().Random(s.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}

	a := s.base.ScalarMul(z).Op(statement.X.ScalarMul(e).OpInv())
	return NewCommitment(a), NewResponse(z), nil
}

func (*protocol[P, F, S]) SpecialSoundness() uint {
	return 2
}

func (s *protocol[P, F, S]) ValidateStatement(statement *Statement[P, F, S], witness *Witness[S]) error {
	//if statement == nil ||
	//	witness == nil ||
	//  statement.Curve().Name() != witness.ScalarField().Curve().Name() ||
	if !s.base.ScalarMul(witness.W).Equal(statement.X) {
		return errs.NewArgument("invalid statement")
	}

	return nil
}

func (s *protocol[P, F, S]) GetChallengeBytesLength() int {
	curve, err := curves.GetCurve(s.base)
	if err != nil {
		panic(err)
	}

	return curve.ScalarField().WideElementSize()
}

func (*protocol[P, F, S]) SerializeStatement(statement *Statement[P, F, S]) []byte {
	return statement.X.ToAffineCompressed()
}

func (*protocol[P, F, S]) SerializeCommitment(commitment *Commitment[P, F, S]) []byte {
	return commitment.A.ToAffineCompressed()
}

func (*protocol[P, F, S]) SerializeResponse(response *Response[S]) []byte {
	return response.Z.Bytes()
}

func (s *protocol[P, F, S]) mapChallengeBytesToChallenge(challengeBytes []byte) (S, error) {
	var sNil S
	curve, err := curves.GetCurve(s.base)
	if err != nil {
		return sNil, errs.WrapFailed(err, "cannot get curve")
	}

	e, err := curve.ScalarField().FromWideBytes(challengeBytes)
	if err != nil {
		return sNil, errs.WrapHashing(err, "cannot hash to scalar")
	}

	return e, nil
}

func (*protocol[P, F, S]) Name() sigma.Name {
	return Name
}
