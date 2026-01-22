package maurer09

import (
	"io"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/errs-go/errs"
)

const (
	specialSoundness = 2
)

// Witness holds the Maurer09 witness.
type Witness[P algebra.GroupElement[P]] struct {
	W P `cbor:"w"`
}

// Bytes encodes the witness.
func (w *Witness[P]) Bytes() []byte {
	return w.W.Bytes()
}

// Value returns the witness group element.
func (w *Witness[P]) Value() P {
	return w.W
}

// Statement holds the Maurer09 statement.
type Statement[I algebra.GroupElement[I]] struct {
	X I `cbor:"x"`
}

// Bytes encodes the statement.
func (x *Statement[I]) Bytes() []byte {
	return x.X.Bytes()
}

// Value returns the statement group element.
func (x *Statement[I]) Value() I {
	return x.X
}

// State stores the prover's internal state.
type State[P algebra.GroupElement[P]] struct {
	S P `cbor:"s"`
}

// Bytes encodes the state.
func (s *State[P]) Bytes() []byte {
	return s.S.Bytes()
}

// Value returns the state group element.
func (s *State[P]) Value() P {
	return s.S
}

// Commitment holds the prover commitment.
type Commitment[I algebra.GroupElement[I]] struct {
	A I `cbor:"a"`
}

// Bytes encodes the commitment.
func (c *Commitment[I]) Bytes() []byte {
	return c.A.Bytes()
}

// Value returns the commitment group element.
func (c *Commitment[I]) Value() I {
	return c.A
}

// Response holds the prover response.
type Response[P algebra.GroupElement[P]] struct {
	Z P `cbor:"z"`
}

// Bytes encodes the response.
func (c *Response[P]) Bytes() []byte {
	return c.Z.Bytes()
}

// Value returns the response group element.
func (c *Response[P]) Value() P {
	return c.Z
}

// MaurerOption configures the Maurer09 protocol.
type MaurerOption[I algebra.GroupElement[I], P algebra.GroupElement[P]] func(protocol *Protocol[I, P])

// WithImageScalarMul overrides the scalar multiplication in the image group.
func WithImageScalarMul[I algebra.GroupElement[I], P algebra.GroupElement[P]](scalarMul func(I, []byte) I) MaurerOption[I, P] {
	return func(protocol *Protocol[I, P]) {
		protocol.imageScalarMul = scalarMul
	}
}

// WithPreImageScalarMul overrides the scalar multiplication in the pre-image group.
func WithPreImageScalarMul[I algebra.GroupElement[I], P algebra.GroupElement[P]](scalarMul func(P, []byte) P) MaurerOption[I, P] {
	return func(protocol *Protocol[I, P]) {
		protocol.preImageScalarMul = scalarMul
	}
}

// Protocol implements the Maurer09 sigma protocol.
type Protocol[I algebra.GroupElement[I], P algebra.GroupElement[P]] struct {
	imageGroup         algebra.FiniteGroup[I]
	preImageGroup      algebra.FiniteGroup[P]
	challengeByteLen   int
	soundnessError     uint
	name               sigma.Name
	oneWayHomomorphism sigma.OneWayHomomorphism[I, P]
	anchor             sigma.Anchor[I, P]
	imageScalarMul     func(I, []byte) I
	preImageScalarMul  func(P, []byte) P
	prng               io.Reader
}

// NewProtocol constructs a Maurer09 protocol instance.
func NewProtocol[I algebra.GroupElement[I], P algebra.GroupElement[P]](
	challengeByteLen int,
	soundnessError uint,
	name sigma.Name,
	imageGroup algebra.FiniteGroup[I],
	preImageGroup algebra.FiniteGroup[P],
	oneWayHomomorphism sigma.OneWayHomomorphism[I, P],
	anchor sigma.Anchor[I, P],
	prng io.Reader,
	options ...MaurerOption[I, P],
) (*Protocol[I, P], error) {
	if challengeByteLen <= 0 || soundnessError < 1 || imageGroup == nil || preImageGroup == nil || oneWayHomomorphism == nil || anchor == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}

	p := &Protocol[I, P]{
		imageGroup:         imageGroup,
		preImageGroup:      preImageGroup,
		challengeByteLen:   challengeByteLen,
		soundnessError:     soundnessError,
		name:               name,
		oneWayHomomorphism: oneWayHomomorphism,
		anchor:             anchor,
		imageScalarMul:     defaultScalarMul[I],
		preImageScalarMul:  defaultScalarMul[P],
		prng:               prng,
	}
	for _, option := range options {
		option(p)
	}
	return p, nil
}

// ComputeProverCommitment creates the Maurer09 commitment and state.
func (p *Protocol[I, P]) ComputeProverCommitment(_ *Statement[I], _ *Witness[P]) (*Commitment[I], *State[P], error) {
	s, err := p.preImageGroup.Random(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample element group")
	}
	a := p.oneWayHomomorphism(s)

	return &Commitment[I]{A: a}, &State[P]{S: s}, nil
}

// ComputeProverResponse computes the Maurer09 response.
func (p *Protocol[I, P]) ComputeProverResponse(_ *Statement[I], witness *Witness[P], _ *Commitment[I], state *State[P], challengeBytes sigma.ChallengeBytes) (*Response[P], error) {
	z := state.S.Op(p.preImageScalarMul(witness.W, challengeBytes))
	return &Response[P]{Z: z}, nil
}

// Verify checks a Maurer09 proof response.
func (p *Protocol[I, P]) Verify(statement *Statement[I], commitment *Commitment[I], challengeBytes sigma.ChallengeBytes, response *Response[P]) error {
	if !p.oneWayHomomorphism(response.Z).Equal(commitment.A.Op(p.imageScalarMul(statement.X, challengeBytes))) {
		return ErrVerificationFailed.WithMessage("invalid response")
	}

	return nil
}

// RunSimulator simulates a Maurer09 transcript for a given challenge.
func (p *Protocol[I, P]) RunSimulator(statement *Statement[I], challengeBytes sigma.ChallengeBytes) (*Commitment[I], *Response[P], error) {
	z, err := p.preImageGroup.Random(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample element group")
	}
	a := p.oneWayHomomorphism(z).Op(p.imageScalarMul(statement.X.OpInv(), challengeBytes))

	return &Commitment[I]{A: a}, &Response[P]{Z: z}, nil
}

// Extract derives the witness from two valid transcripts.
func (p *Protocol[I, P]) Extract(x *Statement[I], a *Commitment[I], ei []sigma.ChallengeBytes, zi []*Response[P]) (*Witness[P], error) {
	if uint(len(ei)) != specialSoundness || uint(len(zi)) != specialSoundness {
		return nil, ErrInvalidArgument.WithMessage("invalid number of challenge bytes")
	}
	if err := p.Verify(x, a, ei[0], zi[0]); err != nil {
		return nil, errs.Wrap(err).WithMessage("verification failed")
	}
	if err := p.Verify(x, a, ei[1], zi[1]); err != nil {
		return nil, errs.Wrap(err).WithMessage("verification failed")
	}

	u := p.anchor.PreImage(x.X)

	// we have to fall back to big.Int here because it's the only way to compute ext GCD
	e1 := new(big.Int).SetBytes(ei[0])
	e2 := new(big.Int).SetBytes(ei[1])
	eDiff := new(big.Int).Sub(e1, e2)
	var g, alpha, beta big.Int
	g.GCD(&alpha, &beta, p.anchor.L().Big(), eDiff)
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil, ErrFailed.WithMessage("BUG: this should never happen")
	}

	w := p.preImageScalarMulI(u, &alpha).Op(p.preImageScalarMulI(zi[1].Z.OpInv().Op(zi[0].Z), &beta))
	return &Witness[P]{W: w}, nil
}

// SpecialSoundness returns the protocol special soundness parameter.
func (*Protocol[I, P]) SpecialSoundness() uint {
	return specialSoundness
}

// ValidateStatement checks statement/witness consistency.
func (p *Protocol[I, P]) ValidateStatement(statement *Statement[I], witness *Witness[P]) error {
	if !p.oneWayHomomorphism(witness.W).Equal(statement.X) {
		return ErrValidationFails.WithMessage("invalid statement")
	}

	return nil
}

// GetChallengeBytesLength returns the challenge size in bytes.
func (p *Protocol[I, P]) GetChallengeBytesLength() int {
	return p.challengeByteLen
}

// Name returns the protocol name.
func (p *Protocol[I, P]) Name() sigma.Name {
	return p.name
}

// SoundnessError returns the protocol soundness error.
func (p *Protocol[G, S]) SoundnessError() uint {
	return p.soundnessError
}

// ImageGroup returns the protocol image group.
func (p *Protocol[I, P]) ImageGroup() algebra.FiniteGroup[I] {
	return p.imageGroup
}

// PreImageGroup returns the protocol pre-image group.
func (p *Protocol[I, P]) PreImageGroup() algebra.FiniteGroup[P] {
	return p.preImageGroup
}

// Phi returns the protocol one-way homomorphism.
func (p *Protocol[I, P]) Phi() sigma.OneWayHomomorphism[I, P] {
	return p.oneWayHomomorphism
}

// Anchor returns the protocol anchor.
func (p *Protocol[I, P]) Anchor() sigma.Anchor[I, P] {
	return p.anchor
}

func (p *Protocol[I, P]) preImageScalarMulI(base P, e *big.Int) P {
	absE := e.Bytes()
	if e.Sign() < 0 {
		return p.preImageScalarMul(base.OpInv(), absE)
	} else {
		return p.preImageScalarMul(base, absE)
	}
}

func defaultScalarMul[G algebra.GroupElement[G]](base G, eBytes []byte) G {
	e, _ := num.N().FromBytes(eBytes)
	return algebrautils.ScalarMul(base, e)
}
