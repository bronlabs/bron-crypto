package batch_schnorr

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	Name sigma.Name = "BATCH_SCHNORR" + dlog.Type
)

var (
	ErrInvalidArgument    = errs2.New("invalid argument")
	ErrValidationFailed   = errs2.New("validation failed")
	ErrVerificationFailed = errs2.New("verification failed")
)

type Statement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Gen G   `cbor:"gen"`
	Xs  []G `cbor:"xs"`
}

func NewStatement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](g G, xs ...G) *Statement[G, S] {
	return &Statement[G, S]{
		Gen: g,
		Xs:  xs,
	}
}

func (x *Statement[G, S]) Bytes() []byte {
	var d []byte

	gBytes := x.Gen.Bytes()
	d = binary.LittleEndian.AppendUint64(d, uint64(len(gBytes)))
	d = append(d, gBytes...)

	t := len(x.Xs)
	d = binary.LittleEndian.AppendUint64(d, uint64(t))
	for _, xi := range x.Xs {
		xBytes := xi.Bytes()
		d = binary.LittleEndian.AppendUint64(d, uint64(len(xBytes)))
		d = append(d, xi.Bytes()...)
	}

	return d
}

type Witness[S algebra.PrimeFieldElement[S]] struct {
	Ws []S `cbor:"ws"`
}

func NewWitness[S algebra.PrimeFieldElement[S]](ws ...S) *Witness[S] {
	return &Witness[S]{
		Ws: ws,
	}
}

func (w *Witness[S]) Bytes() []byte {
	var d []byte

	t := len(w.Ws)
	d = binary.LittleEndian.AppendUint64(d, uint64(t))
	for _, wi := range w.Ws {
		wBytes := wi.Bytes()
		d = binary.LittleEndian.AppendUint64(d, uint64(len(wBytes)))
		d = append(d, wi.Bytes()...)
	}

	return d
}

type Commitment[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	A G `cbor:"a"`
}

func (a *Commitment[G, S]) Bytes() []byte {
	var d []byte

	aBytes := a.A.Bytes()
	d = binary.LittleEndian.AppendUint64(d, uint64(len(aBytes)))
	d = append(d, aBytes...)

	return d
}

type State[S algebra.PrimeFieldElement[S]] struct {
	S S `cbor:"s"`
}

type Response[S algebra.PrimeFieldElement[S]] struct {
	Z S `cbor:"z"`
}

func (z *Response[S]) Bytes() []byte {
	var d []byte

	zBytes := z.Z.Bytes()
	d = binary.LittleEndian.AppendUint64(d, uint64(len(zBytes)))
	d = append(d, zBytes...)

	return d
}

type Protocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	k               int
	challengeLength int
	soundnessError  int
	group           algebra.PrimeGroup[G, S]
	scalarField     algebra.PrimeField[S]
	prng            io.Reader
}

func NewProtocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](k int, group algebra.PrimeGroup[G, S], prng io.Reader) (*Protocol[G, S], error) {
	if k < 2 {
		return nil, ErrInvalidArgument.WithMessage("k must be >= 2")
	}
	if group == nil {
		return nil, ErrInvalidArgument.WithMessage("group is nil")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng is nil")
	}

	challengeLengthBits := base.ComputationalSecurityBits + mathutils.CeilLog2(k)
	challengeLengthBytes := mathutils.CeilDiv(challengeLengthBits, 8)
	soundnessError := challengeLengthBytes*8 - mathutils.CeilLog2(k)
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	p := &Protocol[G, S]{
		k:               k,
		challengeLength: challengeLengthBytes,
		soundnessError:  soundnessError,
		group:           group,
		scalarField:     scalarField,
		prng:            prng,
	}
	return p, nil
}

func (p *Protocol[G, S]) Name() sigma.Name {
	return Name
}

func (p *Protocol[G, S]) ComputeProverCommitment(statement *Statement[G, S], _ *Witness[S]) (*Commitment[G, S], *State[S], error) {
	if statement == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("statement is nil")
	}

	s, err := p.scalarField.Random(p.prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot generate random scalar")
	}
	a := statement.Gen.ScalarOp(s)

	commitment := &Commitment[G, S]{
		A: a,
	}
	state := &State[S]{
		S: s,
	}
	return commitment, state, nil
}

func (p *Protocol[G, S]) ComputeProverResponse(_ *Statement[G, S], witness *Witness[S], _ *Commitment[G, S], state *State[S], challenge sigma.ChallengeBytes) (*Response[S], error) {
	if state == nil {
		return nil, ErrInvalidArgument.WithMessage("state is nil")
	}
	if witness == nil {
		return nil, ErrInvalidArgument.WithMessage("witness is nil")
	}
	if len(witness.Ws) != p.k {
		return nil, ErrInvalidArgument.WithMessage("invalid number of witnesses")
	}
	if len(challenge) != p.challengeLength {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	polyRing, err := polynomials.NewPolynomialRing(p.scalarField)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create polynomial ring")
	}
	coefficients := append([]S{state.S}, witness.Ws...)
	poly, err := polyRing.New(coefficients...)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create polynomial")
	}

	e, err := p.scalarField.FromWideBytes(challenge)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot convert challenge to scalar")
	}

	z := poly.Eval(e)
	response := &Response[S]{
		Z: z,
	}
	return response, nil
}

func (p *Protocol[G, S]) Verify(statement *Statement[G, S], commitment *Commitment[G, S], challenge sigma.ChallengeBytes, response *Response[S]) error {
	if commitment == nil {
		return ErrInvalidArgument.WithMessage("commitment is nil")
	}
	if statement == nil {
		return ErrInvalidArgument.WithMessage("statement is nil")
	}
	if response == nil {
		return ErrInvalidArgument.WithMessage("response is nil")
	}
	if len(statement.Xs) != p.k {
		return ErrVerificationFailed.WithMessage("invalid number of statements")
	}
	if len(challenge) != p.challengeLength {
		return ErrVerificationFailed.WithMessage("invalid challenge length")
	}

	polyModule, err := polynomials.NewPolynomialModule(p.group)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot create polynomial module")
	}
	coefficients := append([]G{commitment.A}, statement.Xs...)
	poly, err := polyModule.New(coefficients...)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot create polynomial")
	}

	e, err := p.scalarField.FromWideBytes(challenge)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot convert challenge to scalar")
	}

	rCheck := poly.Eval(e)
	if !rCheck.Equal(statement.Gen.ScalarOp(response.Z)) {
		return ErrVerificationFailed.WithMessage("invalid proof")
	}

	return nil
}

func (p *Protocol[G, S]) RunSimulator(statement *Statement[G, S], challenge sigma.ChallengeBytes) (*Commitment[G, S], *Response[S], error) {
	z, err := p.scalarField.Random(p.prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot sample random scalar")
	}

	e, err := p.scalarField.FromWideBytes(challenge)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot convert challenge to scalar")
	}

	polyModule, err := polynomials.NewPolynomialModule(p.group)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create polynomial module")
	}
	coefficients := append([]G{p.group.OpIdentity()}, statement.Xs...)
	poly, err := polyModule.New(coefficients...)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create polynomial")
	}
	a := statement.Gen.ScalarOp(z).Op(poly.Eval(e).OpInv())

	commitment := &Commitment[G, S]{
		A: a,
	}
	response := &Response[S]{
		Z: z,
	}
	return commitment, response, nil
}

func (p *Protocol[G, S]) SpecialSoundness() uint {
	return uint(p.k + 1)
}

func (p *Protocol[G, S]) SoundnessError() uint {
	return uint(p.soundnessError)
}

func (p *Protocol[G, S]) GetChallengeBytesLength() int {
	return p.challengeLength
}

func (p *Protocol[G, S]) ValidateStatement(statement *Statement[G, S], witness *Witness[S]) error {
	if statement == nil {
		return ErrInvalidArgument.WithMessage("statement is nil")
	}
	if witness == nil {
		return ErrInvalidArgument.WithMessage("witness is nil")
	}
	if len(statement.Xs) != p.k {
		return ErrValidationFailed.WithMessage("invalid number of statements")
	}
	if len(witness.Ws) != p.k {
		return ErrValidationFailed.WithMessage("invalid number of witnesses")
	}

	for i := range p.k {
		if !statement.Gen.ScalarOp(witness.Ws[i]).Equal(statement.Xs[i]) {
			return ErrValidationFailed.WithMessage("invalid statement")
		}
	}
	return nil
}

func _[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](proto *Protocol[G, S]) {
	var _ sigma.Protocol[*Statement[G, S], *Witness[S], *Commitment[G, S], *State[S], *Response[S]] = proto
}
