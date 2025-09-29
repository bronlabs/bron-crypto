package batch_schnorr2

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	Name sigma.Name = "BATCH_SCHNORR" + dlog.Type
)

var (
	_ sigma.Statement                                                                                                                                                      = (*Statement[*k256.Point, *k256.Scalar])(nil)
	_ sigma.Witness                                                                                                                                                        = (*Witness[*k256.Scalar])(nil)
	_ sigma.Commitment                                                                                                                                                     = (*Commitment[*k256.Point, *k256.Scalar])(nil)
	_ sigma.State                                                                                                                                                          = (*State[*k256.Scalar])(nil)
	_ sigma.Response                                                                                                                                                       = (*Response[*k256.Scalar])(nil)
	_ sigma.Protocol[*Statement[*k256.Point, *k256.Scalar], *Witness[*k256.Scalar], *Commitment[*k256.Point, *k256.Scalar], *State[*k256.Scalar], *Response[*k256.Scalar]] = (*Protocol[*k256.Point, *k256.Scalar])(nil)
)

type Witness[FE algebra.PrimeFieldElement[FE]] struct {
	W []FE `cbor:"w"`
}

func (w *Witness[FE]) Bytes() []byte {
	panic("not implemented")
}

func NewWitness[FE algebra.PrimeFieldElement[FE]](witnesses ...FE) *Witness[FE] {
	return &Witness[FE]{
		W: witnesses,
	}
}

type Statement[GE algebra.PrimeGroupElement[GE, FE], FE algebra.PrimeFieldElement[FE]] struct {
	X []GE `cbor:"x"`
}

func (s *Statement[GE, FE]) Bytes() []byte {
	panic("implement me")
}

func NewStatement[GE algebra.PrimeGroupElement[GE, FE], FE algebra.PrimeFieldElement[FE]](statements ...GE) *Statement[GE, FE] {
	return &Statement[GE, FE]{
		X: statements,
	}
}

type Commitment[GE algebra.PrimeGroupElement[GE, FE], FE algebra.PrimeFieldElement[FE]] struct {
	A GE `cbor:"a"`
}

func (c *Commitment[GE, FE]) Bytes() []byte {
	panic("implement me")
}

type State[FE algebra.PrimeFieldElement[FE]] struct {
	S FE `cbor:"s"`
}

func (s *State[FE]) Bytes() []byte {
	panic("implement me")
}

type Response[FE algebra.PrimeFieldElement[FE]] struct {
	Z FE `cbor:"z"`
}

func (r *Response[FE]) Bytes() []byte {
	panic("implement me")
}

type Protocol[GE algebra.PrimeGroupElement[GE, FE], FE algebra.PrimeFieldElement[FE]] struct {
	baseElement GE
	n           int
	prng        io.Reader
}

func NewProtocol[GE algebra.PrimeGroupElement[GE, FE], FE algebra.PrimeFieldElement[FE]](baseElement GE, n int, prng io.Reader) (*Protocol[GE, FE], error) {
	if baseElement.IsOpIdentity() {
		return nil, errs.NewFailed("base element cannot be identity")
	}
	if n <= 1 {
		return nil, errs.NewFailed("n must be > 1")
	}

	p := &Protocol[GE, FE]{
		baseElement,
		n,
		prng,
	}
	return p, nil
}

func (p *Protocol[GE, FE]) Name() sigma.Name {
	return Name
}

func (p *Protocol[GE, FE]) ComputeProverCommitment(statement *Statement[GE, FE], witness *Witness[FE]) (*Commitment[GE, FE], *State[FE], error) {
	if statement == nil || len(statement.X) != p.n {
		return nil, nil, errs.NewFailed("statement does not have enough elements")
	}
	if witness == nil || len(witness.W) != p.n {
		return nil, nil, errs.NewFailed("witness does not have enough elements")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[GE, FE]](p.baseElement.Structure())
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	s, err := scalarField.Random(p.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample state")
	}
	a := p.baseElement.ScalarOp(s)

	ss := &State[FE]{
		S: s,
	}
	aa := &Commitment[GE, FE]{
		A: a,
	}
	return aa, ss, nil
}

func (p *Protocol[GE, FE]) ComputeProverResponse(_ *Statement[GE, FE], witness *Witness[FE], _ *Commitment[GE, FE], state *State[FE], challenge sigma.ChallengeBytes) (*Response[FE], error) {
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[GE, FE]](p.baseElement.Structure())
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	polyRing, err := polynomials2.NewPolynomialRing(scalarField)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create polynomial ring")
	}
	poly := polyRing.New(append([]FE{state.S}, witness.W...))
	e, err := scalarField.FromWideBytes(challenge)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute scalar")
	}
	z := poly.Eval(e)
	zz := &Response[FE]{
		z,
	}
	return zz, nil
}

func (p *Protocol[GE, FE]) Verify(statement *Statement[GE, FE], commitment *Commitment[GE, FE], challenge sigma.ChallengeBytes, response *Response[FE]) error {
	if len(statement.X) != p.n || len(challenge) != p.GetChallengeBytesLength() {
		return errs.NewVerification("invalid statement/response")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[GE, FE]](p.baseElement.Structure())
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	poly, err := polynomials2.NewModuleValuedPolynomial(append([]GE{commitment.A}, statement.X...))
	if err != nil {
		return errs.WrapFailed(err, "cannot create polynomial")
	}
	e, err := scalarField.FromWideBytes(challenge)
	if err != nil {
		return errs.WrapFailed(err, "cannot compute scalar")
	}
	y := poly.Eval(e)
	if !y.Equal(p.baseElement.ScalarOp(response.Z)) {
		return errs.NewVerification("invalid statement/response")
	}

	return nil
}

func (p *Protocol[GE, FE]) RunSimulator(statement *Statement[GE, FE], challenge sigma.ChallengeBytes) (*Commitment[GE, FE], *Response[FE], error) {
	// TODO: implement
	//if statement == nil {
	//	return nil, nil, errs.NewIsNil("statement")
	//}
	//for _, s := range statement {
	//	if s.Curve().Name() != b.curve.Name() {
	//		return nil, nil, errs.NewArgument("invalid curve")
	//	}
	//}
	//if len(challengeBytes) != b.GetChallengeBytesLength() {
	//	return nil, nil, errs.NewArgument("invalid challenge bytes length")
	//}
	//
	//e, err := b.mapChallengeBytesToChallenge(challengeBytes)
	//if err != nil {
	//	return nil, nil, errs.WrapFailed(err, "cannot map challenge bytes to scalar")
	//}
	//
	//z, err := b.curve.ScalarField().Random(b.prng)
	//if err != nil {
	//	return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	//}
	//
	//coefficients := make([]curves.Point, len(statement)+1)
	//copy(coefficients, statement)
	//coefficients[len(statement)] = b.curve.AdditiveIdentity()
	//
	//a := b.base.ScalarMul(z).Sub(evalPolyInExponentAt(e, coefficients))
	//
	//return a, z, nil
	panic("not implemented")
}

func (p *Protocol[GE, FE]) SpecialSoundness() uint {
	return uint(p.n + 1)
}

func (p *Protocol[GE, FE]) SoundnessError() int {
	return base.ComputationalSecurity
}

func (p *Protocol[GE, FE]) GetChallengeBytesLength() int {
	bitLen := base.ComputationalSecurity + utils.CeilLog2(p.n)
	byteLen := (bitLen + 7) / 8
	return byteLen
}
