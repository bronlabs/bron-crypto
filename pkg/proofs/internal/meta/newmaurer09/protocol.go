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

type FiniteGroup[GE algebra.GroupElement[GE]] interface {
	algebra.Group[GE]
	algebra.FiniteStructure[GE]
}

type OneWayHomomorphism[I algebra.GroupElement[I], P algebra.GroupElement[P]] algebra.Homomorphism[I, P]

type Anchor[I algebra.GroupElement[I], P algebra.GroupElement[P]] interface {
	L() *num.Nat
	// PreImage returns w such that phi(w) == x * L()
	PreImage(x I) (w P)
}

type Witness[P algebra.GroupElement[P]] struct {
	PreImage P `cbor:"w"`
}

func (w *Witness[P]) Bytes() []byte {
	return w.PreImage.Bytes()
}

type Statement[I algebra.GroupElement[I]] struct {
	Image I `cbor:"x"`
}

func (x *Statement[I]) Bytes() []byte {
	return x.Image.Bytes()
}

type State[P algebra.GroupElement[P]] struct {
	PreImage P
}

func (s *State[P]) Bytes() []byte {
	return s.PreImage.Bytes()
}

type Commitment[I algebra.GroupElement[I]] struct {
	Image I `cbor:"a"`
}

func (c *Commitment[I]) Bytes() []byte {
	return c.Image.Bytes()
}

type Response[P algebra.GroupElement[P]] struct {
	PreImage P `cbor:"z"`
}

func (c *Response[P]) Bytes() []byte {
	return c.PreImage.Bytes()
}

type Protocol[I algebra.GroupElement[I], P algebra.GroupElement[P]] struct {
	imageGroup         FiniteGroup[I]
	preImageGroup      FiniteGroup[P]
	challengeByteLen   int
	soundnessError     uint
	name               sigma.Name
	oneWayHomomorphism OneWayHomomorphism[I, P]
	anchor             Anchor[I, P]
	prng               io.Reader
}

func NewProtocol[I algebra.GroupElement[I], P algebra.GroupElement[P]](challengeByteLen int, soundnessError uint, name sigma.Name, imageGroup FiniteGroup[I], preImageGroup FiniteGroup[P], oneWayHomomorphism OneWayHomomorphism[I, P], anchor Anchor[I, P], prng io.Reader) (*Protocol[I, P], error) {
	if challengeByteLen <= 0 || imageGroup == nil || preImageGroup == nil || oneWayHomomorphism == nil || prng == nil {
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

	return &Commitment[I]{Image: a}, &State[P]{PreImage: s}, nil
}

func (p *Protocol[I, P]) ComputeProverResponse(_ *Statement[I], witness *Witness[P], _ *Commitment[I], state *State[P], challengeBytes sigma.ChallengeBytes) (*Response[P], error) {
	e, err := num.N().FromBytes(challengeBytes)
	if err != nil {
		return nil, err
	}
	z := state.PreImage.Op(algebrautils.ScalarMul(witness.PreImage, e))
	return &Response[P]{PreImage: z}, nil
}

func (p *Protocol[I, P]) Verify(statement *Statement[I], commitment *Commitment[I], challengeBytes sigma.ChallengeBytes, response *Response[P]) error {
	e, err := num.N().FromBytes(challengeBytes)
	if err != nil {
		return err
	}
	if !p.oneWayHomomorphism(response.PreImage).Equal(commitment.Image.Op(algebrautils.ScalarMul(statement.Image, e))) {
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
	a := p.oneWayHomomorphism(z).Op(algebrautils.ScalarMul(statement.Image.OpInv(), e))

	return &Commitment[I]{Image: a}, &Response[P]{PreImage: z}, nil
}

func (p *Protocol[I, P]) Extract(x *Statement[I], a *Commitment[I], ei []sigma.ChallengeBytes, zi []*Response[P]) (*Witness[P], error) {
	if uint(len(ei)) != p.SpecialSoundness() || uint(len(zi)) != p.SpecialSoundness() {
		return nil, errs.NewSize("invalid number of challenge bytes")
	}
	if err := p.Verify(x, a, ei[0], zi[0]); err != nil {
		return nil, errs.WrapVerification(err, "verification failed")
	}
	if err := p.Verify(x, a, ei[1], zi[1]); err != nil {
		return nil, errs.WrapVerification(err, "verification failed")
	}

	u := p.anchor.PreImage(x.Image)

	// we have to fall back to big.Int here because it's the only way to compute ext GCD
	e1 := new(big.Int).SetBytes(ei[0])
	e2 := new(big.Int).SetBytes(ei[1])
	eDiff := new(big.Int).Sub(e1, e2)
	var g, alpha, beta big.Int
	g.GCD(&alpha, &beta, p.anchor.L().Big(), eDiff)
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil, errs.NewValidation("BUG: this should never happen")
	}

	w := scalarMul(u, &alpha).Op(scalarMul(zi[1].PreImage.OpInv().Op(zi[0].PreImage), &beta))
	return &Witness[P]{PreImage: w}, nil
}

func (p *Protocol[I, P]) SpecialSoundness() uint {
	return 2
}

func (p *Protocol[I, P]) ValidateStatement(statement *Statement[I], witness *Witness[P]) error {
	if !p.oneWayHomomorphism(witness.PreImage).Equal(statement.Image) {
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

func (p *Protocol[I, P]) Phi() OneWayHomomorphism[I, P] {
	return p.oneWayHomomorphism
}

func scalarMul[G algebra.GroupElement[G]](base G, e *big.Int) G {
	absE, _ := num.N().FromBytes(e.Bytes())
	if e.Sign() < 0 {
		return algebrautils.ScalarMul(base.OpInv(), absE)
	} else {
		return algebrautils.ScalarMul(base, absE)
	}
}
