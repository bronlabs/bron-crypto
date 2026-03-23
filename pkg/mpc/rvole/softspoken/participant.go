package rvole_softspoken

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
)

const (
	transcriptLabel = "BRON_CRYPTO_SOFTSPOKEN_OT_MULTIPLY-"
	gadgetLabel     = "BRON_CRYPTO_SOFTSPOKEN_OT_MULTIPLY-G-"
	aTildeLabel     = "BRON_CRYPTO_SOFTSPOKEN_OT_MULTIPLY-A_TILDE-"
	thetaLabel      = "BRON_CRYPTO_SOFTSPOKEN_OT_MULTIPLY-THETA-"
	muVectorLabel   = "BRON_CRYPTO_SOFTSPOKEN_OT_MULTIPLY-MU_VECTOR-"
	muLabel         = "BRON_CRYPTO_SOFTSPOKEN_OT_MULTIPLY-MU-"
)

type participant[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx   *session.Context
	suite *Suite[P, B, S]
	xi    int
	rho   int
	prng  io.Reader
	round int
}

// Alice represents the sender party.
type Alice[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant[P, B, S]

	sender *softspoken.Sender
	g      []S
	alpha  [][2][]S
}

// Bob represents the receiver party.
type Bob[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant[P, B, S]

	receiver *softspoken.Receiver
	g        []S
	beta     []byte
	gamma    [][]S
}

func newParticipant[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[P, B, S], prng io.Reader, initialRound int) (*participant[P, B, S], error) {
	if suite == nil || prng == nil || ctx == nil {
		return nil, ErrNil.WithMessage("argument")
	}

	kappa := suite.field.ElementSize() * 8
	xi := kappa + base.CollisionResistance // normally this should be statistical security, but then xi is an invalid parameter for softspoken
	rho := mathutils.CeilDiv(kappa, base.ComputationalSecurityBits)

	sessionID := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	return &participant[P, B, S]{
		ctx:   ctx,
		suite: suite,
		xi:    xi,
		rho:   rho,
		prng:  prng,
		round: initialRound,
	}, nil
}

// NewAlice returns a new Alice participant.
func NewAlice[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[P, B, S], seeds *vsot.ReceiverOutput, prng io.Reader) (*Alice[P, B, S], error) {
	p, err := newParticipant(ctx, suite, prng, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create participant / gadget vector")
	}
	softspokenSuite, err := softspoken.NewSuite(p.xi, suite.l+p.rho, suite.hashFunc)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create softspoken suite")
	}

	sender, err := softspoken.NewSender(ctx, seeds, softspokenSuite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create sender")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create gadget vector")
	}

	//nolint:exhaustruct // lazy initialisation
	alice := &Alice[P, B, S]{
		participant: *p,
		sender:      sender,
		g:           gadget,
	}
	return alice, nil
}

// NewBob returns a new Bob participant.
func NewBob[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[P, B, S], seeds *vsot.SenderOutput, prng io.Reader) (*Bob[P, B, S], error) {
	p, err := newParticipant(ctx, suite, prng, 1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create participant / gadget vector")
	}
	softspokenSuite, err := softspoken.NewSuite(p.xi, suite.l+p.rho, suite.hashFunc)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create softspoken suite")
	}

	receiver, err := softspoken.NewReceiver(ctx, seeds, softspokenSuite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create receiver")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create gadget vector")
	}

	//nolint:exhaustruct // lazy initialisation
	bob := &Bob[P, B, S]{
		participant: *p,
		receiver:    receiver,
		g:           gadget,
	}
	return bob, nil
}

func (p *participant[P, B, S]) generateGadgetVector() ([]S, error) {
	gadget := make([]S, p.xi)
	for i := range gadget {
		bytes, err := p.ctx.Transcript().ExtractBytes(gadgetLabel, uint(p.suite.field.WideElementSize()))
		if err != nil {
			return gadget, errs.Wrap(err).WithMessage("extracting bytes from transcript")
		}
		gadget[i], err = p.suite.field.FromWideBytes(bytes)
		if err != nil {
			return gadget, errs.Wrap(err).WithMessage("creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}
