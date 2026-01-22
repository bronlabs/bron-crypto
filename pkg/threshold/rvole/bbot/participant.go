package rvole_bbot

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/pkg/errs"
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
	sessionID network.SID
	suite     *Suite[G, S]
	xi, rho   int
	tape      transcripts.Transcript
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

func newParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](sessionID network.SID, suite *Suite[G, S], prng io.Reader, tape transcripts.Transcript, initialRound int) (*participant[G, S], error) {
	if suite == nil || prng == nil || tape == nil || initialRound < 1 {
		return nil, ErrNil.WithMessage("argument")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	kappa := suite.group.ScalarStructure().ElementSize() * 8
	xi := kappa + 2*base.StatisticalSecurityBits
	rho := mathutils.CeilDiv(kappa, base.ComputationalSecurityBits)

	return &participant[G, S]{
		prng:      prng,
		round:     initialRound,
		sessionID: sessionID,
		suite:     suite,
		tape:      tape,
		xi:        xi,
		rho:       rho,
	}, nil
}

// NewAlice returns a new Alice participant.
func NewAlice[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](sessionID network.SID, suite *Suite[G, S], prng io.Reader, tape transcripts.Transcript) (*Alice[G, S], error) {
	p, err := newParticipant(sessionID, suite, prng, tape, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create participant / gadget vector")
	}
	otSuite, err := ecbbot.NewSuite(p.xi, p.suite.l+p.rho, p.suite.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ecbbot suite")
	}
	sender, err := ecbbot.NewSender(p.sessionID, otSuite, tape, prng)
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
func NewBob[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](sessionID network.SID, suite *Suite[G, S], prng io.Reader, tape transcripts.Transcript) (*Bob[G, S], error) {
	p, err := newParticipant(sessionID, suite, prng, tape, 1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create participant / gadget vector")
	}
	otSuite, err := ecbbot.NewSuite(p.xi, p.suite.l+p.rho, p.suite.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ecbbot suite")
	}
	receiver, err := ecbbot.NewReceiver(p.sessionID, otSuite, tape, prng)
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
		bytes, err := p.tape.ExtractBytes(gadgetLabel, uint(p.suite.field.WideElementSize()))
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
