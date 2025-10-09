package rvole_softspoken

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
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
	sessionId network.SID
	suite     *Suite[P, B, S]
	xi        int
	rho       int
	tape      transcripts.Transcript
	prng      io.Reader
	round     int
}

type Alice[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant[P, B, S]
	sender *softspoken.Sender
	g      []S
	alpha  [][2][]S
}

type Bob[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant[P, B, S]
	receiver *softspoken.Receiver
	g        []S
	beta     []byte
	gamma    [][]S
}

func newParticipant[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, suite *Suite[P, B, S], prng io.Reader, tape transcripts.Transcript, initialRound int) (*participant[P, B, S], error) {
	if suite == nil || prng == nil || tape == nil {
		return nil, errs.NewIsNil("argument")
	}

	kappa := suite.field.ElementSize() * 8
	xi := kappa + base.CollisionResistance // normally this should be statistical security, but then xi is an invalid parameter for softspoken
	rho := utils.CeilDiv(kappa, base.ComputationalSecurityBits)

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	return &participant[P, B, S]{
		sessionId: sessionId,
		suite:     suite,
		xi:        xi,
		rho:       rho,
		tape:      tape,
		prng:      prng,
		round:     initialRound,
	}, nil
}

func NewAlice[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, suite *Suite[P, B, S], seeds *vsot.ReceiverOutput, prng io.Reader, tape transcripts.Transcript) (*Alice[P, B, S], error) {
	p, err := newParticipant(sessionId, suite, prng, tape, 2)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	softspokenSuite, err := softspoken.NewSuite(p.xi, suite.l+p.rho, suite.hashFunc)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create softspoken suite")
	}

	sender, err := softspoken.NewSender(sessionId, seeds, softspokenSuite, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create sender")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}

	alice := &Alice[P, B, S]{
		participant: *p,
		sender:      sender,
		g:           gadget,
	}
	return alice, nil
}

func NewBob[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, suite *Suite[P, B, S], seeds *vsot.SenderOutput, prng io.Reader, tape transcripts.Transcript) (*Bob[P, B, S], error) {
	p, err := newParticipant(sessionId, suite, prng, tape, 1)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	softspokenSuite, err := softspoken.NewSuite(p.xi, suite.l+p.rho, suite.hashFunc)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create softspoken suite")
	}

	receiver, err := softspoken.NewReceiver(sessionId, seeds, softspokenSuite, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create receiver")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}

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
		bytes, err := p.tape.ExtractBytes(gadgetLabel, uint(p.suite.field.WideElementSize()))
		if err != nil {
			return gadget, errs.WrapFailed(err, "extracting bytes from transcript")
		}
		gadget[i], err = p.suite.field.FromWideBytes(bytes)
		if err != nil {
			return gadget, errs.WrapFailed(err, "creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}
