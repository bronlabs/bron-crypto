package rvole_bbot

import (
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

const (
	transcriptLabel = "BRON_CRYPTO_BBOT_MULTIPLY-"
	gadgetLabel     = "BRON_CRYPTO_BBOT_MULTIPLY-G-"
	aTildeLabel     = "BRON_CRYPTO_BBOT_MULTIPLY-A_TILDE-"
	thetaLabel      = "BRON_CRYPTO_BBOT_MULTIPLY-THETA-"
	muVectorLabel   = "BRON_CRYPTO_BBOT_MULTIPLY-MU_VECTOR-"
	muLabel         = "BRON_CRYPTO_BBOT_MULTIPLY-MU-"
)

type participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ctx       *session.Context
	copartyID sharing.ID
	suite     *Suite[G, S]
	xi, rho   int
	prng      io.Reader
	round     int
}

// Alice represents the sender party.
type Alice[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant[G, S] // Base Participant

	sender *ecbbot.Sender[G, S]
	g      []S
	alpha  [][2][]S
}

// Bob represents the receiver party.
type Bob[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant[G, S] // Base Participant

	receiver *ecbbot.Receiver[G, S]
	g        []S
	beta     []byte
	gamma    [][]S
}

func newParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[G, S], prng io.Reader, initialRound int) (*participant[G, S], error) {
	if suite == nil || prng == nil || ctx == nil || initialRound < 1 {
		return nil, ErrNil.WithMessage("argument")
	}
	if ctx.Quorum().Size() != 2 {
		return nil, ErrValidation.WithMessage("invalid quorum size")
	}

	copartyID := slices.Collect(ctx.OtherPartiesOrdered())[0]
	sessionID := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	kappa := suite.group.ScalarStructure().ElementSize() * 8
	xi := kappa + 2*base.StatisticalSecurityBits
	rho := mathutils.CeilDiv(kappa, base.ComputationalSecurityBits)

	return &participant[G, S]{
		ctx:       ctx,
		copartyID: copartyID,
		prng:      prng,
		round:     initialRound,
		suite:     suite,
		xi:        xi,
		rho:       rho,
	}, nil
}

// NewAlice returns a new Alice participant.
func NewAlice[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[G, S], prng io.Reader) (*Alice[G, S], error) {
	p, err := newParticipant(ctx, suite, prng, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create participant / gadget vector")
	}
	otSuite, err := ecbbot.NewSuite(p.xi, p.suite.l+p.rho, p.suite.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ecbbot suite")
	}
	sender, err := ecbbot.NewSender(ctx, otSuite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create sender")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create gadget vector")
	}

	//nolint:exhaustruct // lazy initialisation
	alice := &Alice[G, S]{
		participant: *p,
		sender:      sender,
		g:           gadget,
	}
	alice.round = 1
	return alice, nil
}

// NewBob returns a new Bob participant.
func NewBob[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[G, S], prng io.Reader) (*Bob[G, S], error) {
	p, err := newParticipant(ctx, suite, prng, 1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create participant / gadget vector")
	}
	otSuite, err := ecbbot.NewSuite(p.xi, p.suite.l+p.rho, p.suite.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ecbbot suite")
	}
	receiver, err := ecbbot.NewReceiver(ctx, otSuite, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create receiver")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create gadget vector")
	}

	//nolint:exhaustruct // lazy initialisation
	bob := &Bob[G, S]{
		participant: *p,
		receiver:    receiver,
		g:           gadget,
	}
	bob.round = 2
	return bob, nil
}

func (p *participant[G, S]) generateGadgetVector() ([]S, error) {
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
