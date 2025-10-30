package maurer09

// TODO: add Maurer09 interface
// TODO: keep this implementation internal and not usable outside proofs

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name = "ZKPOK_MAURER09-"

type (
	PreImageGroup[A PreImageGroupElement[A]]        algebra.Group[A]
	PreImageGroupElement[A algebra.GroupElement[A]] algebra.GroupElement[A]

	ImageGroup[B ImageGroupElement[B]]           algebra.Group[B]
	ImageGroupElement[B algebra.GroupElement[B]] algebra.GroupElement[B]

	GroupHomomorphism[A PreImageGroupElement[A], B ImageGroupElement[B]] = algebra.Homomorphism[A, B]

	ChallengeSpace[C Challenge[C]]                                       algebra.NLike[C]
	Challenge[C algebra.NatLike[C]]                                      algebra.NatLike[C]
	ChallengeActionOnPreImage[C Challenge[C], A PreImageGroupElement[A]] algebra.Action[C, A]
	ChallengeActionOnImage[C Challenge[C], B ImageGroupElement[B]]       algebra.Action[C, B]
)

type Statement[A PreImageGroupElement[A], B ImageGroupElement[B]] struct {
	X B `cbor:"x"`
}

func (s *Statement[A, B]) Value() B {
	return s.X
}

func (s *Statement[A, B]) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.X.Bytes()
}

type Witness[A PreImageGroupElement[A]] struct {
	W A `cbor:"w"`
}

func (w *Witness[A]) Value() A {
	return w.W
}

func (w *Witness[A]) Bytes() []byte {
	if w == nil {
		return nil
	}
	return w.W.Bytes()
}

type Commitment[A PreImageGroupElement[A], B ImageGroupElement[B]] struct {
	C B `cbor:"c"`
}

func (c *Commitment[A, B]) Value() B {
	return c.C
}

func (c *Commitment[A, B]) Bytes() []byte {
	if c == nil {
		return nil
	}
	return c.C.Bytes()
}

type State[A PreImageGroupElement[A]] struct {
	K A
}

func (s *State[A]) Value() A {
	return s.K
}

func (s *State[A]) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.K.Bytes()
}

type Response[A PreImageGroupElement[A]] struct {
	Z A
}

func (r *Response[A]) Value() A {
	return r.Z
}

func (r *Response[A]) Bytes() []byte {
	if r == nil {
		return nil
	}
	return r.Z.Bytes()
}

type Protocol[A PreImageGroupElement[A], B ImageGroupElement[B], C Challenge[C], PIG PreImageGroup[A], IG ImageGroup[B]] struct {
	phi                   GroupHomomorphism[A, B]
	preImage              PIG
	image                 IG
	preImageRandomSampler func(io.Reader) (A, error)
	challengeSpace        ChallengeSpace[C]
	preImageScMul         ChallengeActionOnPreImage[C, A]
	imageScMul            ChallengeActionOnImage[C, B]
	prng                  io.Reader
}

func NewProtocol[A PreImageGroupElement[A], B ImageGroupElement[B], C Challenge[C], PIG PreImageGroup[A], IG ImageGroup[B]](
	phi GroupHomomorphism[A, B],
	preImage PIG,
	image IG,
	challengeSpace ChallengeSpace[C],
	preImageScMul ChallengeActionOnPreImage[C, A],
	imageScMul ChallengeActionOnImage[C, B],
	preImageRandomSampler func(io.Reader) (A, error),
	prng io.Reader,
) (*Protocol[A, B, C, PIG, IG], error) {
	if phi == nil {
		return nil, errs.NewIsNil("phi")
	}
	if utils.IsNil(preImage) {
		return nil, errs.NewIsNil("preImage")
	}
	if utils.IsNil(image) {
		return nil, errs.NewIsNil("image")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	if challengeSpace == nil {
		return nil, errs.NewIsNil("challengeSpace")
	}
	if preImageScMul == nil {
		return nil, errs.NewIsNil("preImageScMul")
	}
	if imageScMul == nil {
		return nil, errs.NewIsNil("imageScMul")
	}
	if preImageRandomSampler == nil {
		return nil, errs.NewIsNil("preImageRandomSampler")
	}
	return &Protocol[A, B, C, PIG, IG]{
		phi:                   phi,
		preImage:              preImage,
		image:                 image,
		prng:                  prng,
		challengeSpace:        challengeSpace,
		preImageScMul:         preImageScMul,
		imageScMul:            imageScMul,
		preImageRandomSampler: preImageRandomSampler,
	}, nil
}

func (p *Protocol[A, B, C, PIG, IG]) ComputeProverCommitment(_ *Statement[A, B], _ *Witness[A]) (*Commitment[A, B], *State[A], error) {
	k, err := p.preImageRandomSampler(p.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}
	K := p.phi(k)

	return &Commitment[A, B]{C: K}, &State[A]{K: k}, nil
}

func (p *Protocol[A, B, C, PIG, IG]) ComputeProverResponse(_ *Statement[A, B], witness *Witness[A], _ *Commitment[A, B], state *State[A], challengeBytes sigma.ChallengeBytes) (*Response[A], error) {
	if len(challengeBytes) != p.GetChallengeBytesLength() {
		return nil, errs.NewIsNil("invalid challenge bytes length")
	}
	c, err := p.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, errs.WrapArgument(err, "cannot hash to scalar")
	}
	s := state.K.Op(p.preImageScMul(c, witness.W))
	return &Response[A]{Z: s}, nil
}

func (p *Protocol[A, B, C, PIG, IG]) Verify(statement *Statement[A, B], commitment *Commitment[A, B], challengeBytes sigma.ChallengeBytes, response *Response[A]) error {
	if len(challengeBytes) != p.GetChallengeBytesLength() {
		return errs.NewArgument("invalid challenge bytes length")
	}
	c, err := p.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return errs.WrapArgument(err, "cannot hash to scalar")
	}

	left := p.phi(response.Z)
	right := p.imageScMul(c, statement.X).Op(commitment.C)
	if !left.Equal(right) {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (p *Protocol[A, B, C, PIG, IG]) RunSimulator(statement *Statement[A, B], challengeBytes sigma.ChallengeBytes) (*Commitment[A, B], *Response[A], error) {
	if len(challengeBytes) != p.GetChallengeBytesLength() {
		return nil, nil, errs.NewArgument("invalid challenge bytes length")
	}

	c, err := p.mapChallengeBytesToChallenge(challengeBytes)
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot map to scalar")
	}

	z, err := p.preImageRandomSampler(p.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}

	a := p.phi(z).Op(p.imageScMul(c, statement.X).OpInv())
	return &Commitment[A, B]{C: a}, &Response[A]{Z: z}, nil
}

func (s *Protocol[_, _, _, _, _]) SoundnessError() uint {
	return uint(s.GetChallengeBytesLength()) * 8
}

func (*Protocol[_, _, _, _, _]) SpecialSoundness() uint {
	return 2
}

func (s *Protocol[A, B, C, PIG, IG]) ValidateStatement(statement *Statement[A, B], witness *Witness[A]) error {
	if statement == nil {
		return errs.NewIsNil("statement is nil")
	}
	if witness == nil {
		return errs.NewIsNil("witness is nil")
	}
	if !s.phi(witness.W).Equal(statement.X) {
		return errs.NewValidation("invalid statement")
	}
	return nil
}

func (p *Protocol[A, B, C, PIG, IG]) GetChallengeBytesLength() int {
	return p.preImage.ElementSize()
}

func (p *Protocol[A, B, C, PIG, IG]) mapChallengeBytesToChallenge(challengeBytes []byte) (C, error) {
	c, err := p.challengeSpace.FromBytes(challengeBytes)
	if err != nil {
		return *new(C), errs.WrapHashing(err, "cannot hash to scalar")
	}
	return c, nil
}

func (p *Protocol[A, B, C, PIG, IG]) Phi() GroupHomomorphism[A, B] {
	return p.phi
}

func (p *Protocol[A, B, C, PIG, IG]) PreImageGroup() PIG {
	return p.preImage
}

func (p *Protocol[A, B, C, PIG, IG]) ImageGroup() IG {
	return p.image
}

func (p *Protocol[A, B, C, PIG, IG]) ChallengeActionOnPreImage(c sigma.ChallengeBytes, x A) (A, error) {
	ch, err := p.mapChallengeBytesToChallenge(c)
	if err != nil {
		return *new(A), errs.WrapArgument(err, "cannot map challenge bytes to challenge")
	}
	return p.preImageScMul(ch, x), nil
}

func (p *Protocol[A, B, C, PIG, IG]) ChallengeActionOnImage(c sigma.ChallengeBytes, x B) (B, error) {
	ch, err := p.mapChallengeBytesToChallenge(c)
	if err != nil {
		return *new(B), errs.WrapArgument(err, "cannot map challenge bytes to challenge")
	}
	return p.imageScMul(ch, x), nil
}
