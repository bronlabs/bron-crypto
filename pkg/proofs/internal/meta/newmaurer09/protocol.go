package newmaurer09

import (
	"io"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	specialSoundness = 2
)

type Witness[P algebra.GroupElement[P]] struct {
	W P `cbor:"w"`
}

func (w *Witness[P]) Bytes() []byte {
	return w.W.Bytes()
}

func (w *Witness[P]) Value() P {
	return w.W
}

type Statement[I algebra.GroupElement[I]] struct {
	X I `cbor:"x"`
}

func (x *Statement[I]) Bytes() []byte {
	return x.X.Bytes()
}

func (x *Statement[I]) Value() I {
	return x.X
}

type State[P algebra.GroupElement[P]] struct {
	S P `cbor:"s"`
}

func (s *State[P]) Bytes() []byte {
	return s.S.Bytes()
}

func (s *State[P]) Value() P {
	return s.S
}

type Commitment[I algebra.GroupElement[I]] struct {
	A I `cbor:"a"`
}

func (c *Commitment[I]) Bytes() []byte {
	return c.A.Bytes()
}

func (c *Commitment[I]) Value() I {
	return c.A
}

type Response[P algebra.GroupElement[P]] struct {
	Z P `cbor:"z"`
}

func (c *Response[P]) Bytes() []byte {
	return c.Z.Bytes()
}

func (c *Response[P]) Value() P {
	return c.Z
}

type Protocol[I algebra.GroupElement[I], P algebra.GroupElement[P]] struct {
	imageGroup         sigma.FiniteGroup[I]
	preImageGroup      sigma.FiniteGroup[P]
	challengeByteLen   int
	soundnessError     uint
	name               sigma.Name
	oneWayHomomorphism sigma.OneWayHomomorphism[I, P]
	anchor             sigma.Anchor[I, P]
	prng               io.Reader
}

func NewProtocol[I algebra.GroupElement[I], P algebra.GroupElement[P]](
	challengeByteLen int,
	soundnessError uint,
	name sigma.Name,
	imageGroup sigma.FiniteGroup[I],
	preImageGroup sigma.FiniteGroup[P],
	oneWayHomomorphism sigma.OneWayHomomorphism[I, P],
	anchor sigma.Anchor[I, P],
	prng io.Reader,
) (*Protocol[I, P], error) {
	if challengeByteLen <= 0 || soundnessError < 1 || imageGroup == nil || preImageGroup == nil || oneWayHomomorphism == nil || anchor == nil || prng == nil {
		return nil, errs.NewArgument("invalid arguments")
	}

	p := &Protocol[I, P]{
		imageGroup:         imageGroup,
		preImageGroup:      preImageGroup,
		challengeByteLen:   challengeByteLen,
		soundnessError:     soundnessError,
		name:               name,
		oneWayHomomorphism: oneWayHomomorphism,
		anchor:             anchor,
		prng:               prng,
	}
	return p, nil
}

func (p *Protocol[I, P]) ComputeProverCommitment(_ *Statement[I], _ *Witness[P]) (*Commitment[I], *State[P], error) {
	s, err := p.preImageGroup.Random(p.prng)
	if err != nil {
		return nil, nil, err
	}
	a := p.oneWayHomomorphism(s)

	return &Commitment[I]{A: a}, &State[P]{S: s}, nil
}

func (p *Protocol[I, P]) ComputeProverResponse(_ *Statement[I], witness *Witness[P], _ *Commitment[I], state *State[P], challengeBytes sigma.ChallengeBytes) (*Response[P], error) {
	e, err := num.N().FromBytes(challengeBytes)
	if err != nil {
		return nil, err
	}
	z := state.S.Op(algebrautils.ScalarMul(witness.W, e))
	return &Response[P]{Z: z}, nil
}

func (p *Protocol[I, P]) Verify(statement *Statement[I], commitment *Commitment[I], challengeBytes sigma.ChallengeBytes, response *Response[P]) error {
	e, err := num.N().FromBytes(challengeBytes)
	if err != nil {
		return err
	}
	if !p.oneWayHomomorphism(response.Z).Equal(commitment.A.Op(algebrautils.ScalarMul(statement.X, e))) {
		return errs.NewVerification("invalid response")
	}

	return nil
}

func (p *Protocol[I, P]) RunSimulator(statement *Statement[I], challengeBytes sigma.ChallengeBytes) (*Commitment[I], *Response[P], error) {
	e, err := num.N().FromBytes(challengeBytes)
	if err != nil {
		return nil, nil, err
	}
	z, err := p.preImageGroup.Random(p.prng)
	if err != nil {
		return nil, nil, err
	}
	a := p.oneWayHomomorphism(z).Op(algebrautils.ScalarMul(statement.X.OpInv(), e))

	return &Commitment[I]{A: a}, &Response[P]{Z: z}, nil
}

func (p *Protocol[I, P]) Extract(x *Statement[I], a *Commitment[I], ei []sigma.ChallengeBytes, zi []*Response[P]) (*Witness[P], error) {
	if uint(len(ei)) != specialSoundness || uint(len(zi)) != specialSoundness {
		return nil, errs.NewSize("invalid number of challenge bytes")
	}
	if err := p.Verify(x, a, ei[0], zi[0]); err != nil {
		return nil, errs.WrapVerification(err, "verification failed")
	}
	if err := p.Verify(x, a, ei[1], zi[1]); err != nil {
		return nil, errs.WrapVerification(err, "verification failed")
	}

	u := p.anchor.PreImage(x.X)

	// we have to fall back to big.Int here because it's the only way to compute ext GCD
	e1 := new(big.Int).SetBytes(ei[0])
	e2 := new(big.Int).SetBytes(ei[1])
	eDiff := new(big.Int).Sub(e1, e2)
	var g, alpha, beta big.Int
	g.GCD(&alpha, &beta, p.anchor.L().Big(), eDiff)
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil, errs.NewValidation("BUG: this should never happen")
	}

	w := scalarMul(u, &alpha).Op(scalarMul(zi[1].Z.OpInv().Op(zi[0].Z), &beta))
	return &Witness[P]{W: w}, nil
}

func (p *Protocol[I, P]) SpecialSoundness() uint {
	return specialSoundness
}

func (p *Protocol[I, P]) ValidateStatement(statement *Statement[I], witness *Witness[P]) error {
	if !p.oneWayHomomorphism(witness.W).Equal(statement.X) {
		return errs.NewValidation("invalid statement")
	}

	return nil
}

func (p *Protocol[I, P]) GetChallengeBytesLength() int {
	return p.challengeByteLen
}

func (p *Protocol[I, P]) Name() sigma.Name {
	return p.name
}

func (p *Protocol[G, S]) SoundnessError() uint {
	return p.soundnessError
}

func (p *Protocol[I, P]) ImageGroup() sigma.FiniteGroup[I] {
	return p.imageGroup
}

func (p *Protocol[I, P]) PreImageGroup() sigma.FiniteGroup[P] {
	return p.preImageGroup
}

func (p *Protocol[I, P]) Phi() sigma.OneWayHomomorphism[I, P] {
	return p.oneWayHomomorphism
}

func (p *Protocol[I, P]) Anchor() sigma.Anchor[I, P] {
	return p.anchor
}

func scalarMul[G algebra.GroupElement[G]](base G, e *big.Int) G {
	absE, _ := num.N().FromBytes(e.Bytes())
	if e.Sign() < 0 {
		return algebrautils.ScalarMul(base.OpInv(), absE)
	} else {
		return algebrautils.ScalarMul(base, absE)
	}
}
