package mul_bbot

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_BBOT_MULTIPLY-"
	gadgetLabel     = "BRON_CRYPTO_BBOT_MULTIPLY-G-"
	aTildeLabel     = "BRON_CRYPTO_BBOT_MULTIPLY-A_TILDE-"
	thetaLabel      = "BRON_CRYPTO_BBOT_MULTIPLY-THETA-"
	muVectorLabel   = "BRON_CRYPTO_BBOT_MULTIPLY-MU_VECTOR-"
	muLabel         = "BRON_CRYPTO_BBOT_MULTIPLY-MU-"
)

type participant[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	SessionId   network.SID
	Group       algebra.PrimeGroup[GE, SE]
	ScalarField algebra.PrimeField[SE]
	L, Xi, Rho  int
	Tape        transcripts.Transcript
	Prng        io.Reader
	Round       int
}

type Alice[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	participant[GE, SE] // Base Participant

	sender *ecbbot.Sender[GE, SE]
	g      []SE
	alpha  [][2][]SE
}

type Bob[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	participant[GE, SE] // Base Participant

	receiver *ecbbot.Receiver[GE, SE]
	g        []SE
	beta     []byte
	gamma    [][]SE
}

func newParticipant[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](sessionId network.SID, group algebra.PrimeGroup[GE, SE], l int, prng io.Reader, tape transcripts.Transcript, initialRound int) (*participant[GE, SE], error) {
	// if err := validateParticipantInputs(myAuthKey, protocol, sessionId, prng); err != nil {
	//	return nil, errs.WrapFailed(err, "invalid inputs")
	//}

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	scalarField, ok := group.ScalarStructure().(algebra.PrimeField[SE])
	if !ok {
		return nil, errs.NewFailed("couldn't initialise scalarField")
	}
	kappa := group.ScalarStructure().ElementSize() * 8
	xi := kappa + 2*base.StatisticalSecurity
	rho := utils.CeilDiv(kappa, base.ComputationalSecurity)

	return &participant[GE, SE]{
		Prng:        prng,
		Round:       initialRound,
		SessionId:   sessionId,
		Group:       group,
		ScalarField: scalarField,
		Tape:        tape,
		L:           l,
		Xi:          xi,
		Rho:         rho,
	}, nil
}

func NewAlice[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](sessionId network.SID, group algebra.PrimeGroup[GE, SE], l int, prng io.Reader, tape transcripts.Transcript) (*Alice[GE, SE], error) {
	p, err := newParticipant(sessionId, group, l, prng, tape, 2)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	sender, err := ecbbot.NewSender(p.SessionId, p.Group, p.Xi, p.L+p.Rho, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create sender")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}

	alice := &Alice[GE, SE]{
		participant: *p,
		sender:      sender,
		g:           gadget,
	}
	alice.Round = 1
	return alice, nil
}

func NewBob[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](sessionId network.SID, group algebra.PrimeGroup[GE, SE], l int, prng io.Reader, tape transcripts.Transcript) (*Bob[GE, SE], error) {
	p, err := newParticipant(sessionId, group, l, prng, tape, 1)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	receiver, err := ecbbot.NewReceiver(p.SessionId, group, p.Xi, p.L+p.Rho, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create receiver")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}

	bob := &Bob[GE, SE]{
		participant: *p,
		receiver:    receiver,
		g:           gadget,
	}
	bob.Round = 2
	return bob, nil
}

func (p *participant[GE, SE]) generateGadgetVector() ([]SE, error) {
	gadget := make([]SE, p.Xi)
	for i := range gadget {
		bytes, err := p.Tape.ExtractBytes(gadgetLabel, uint(p.ScalarField.WideElementSize()))
		if err != nil {
			return gadget, errs.WrapFailed(err, "extracting bytes from transcript")
		}
		gadget[i], err = p.ScalarField.FromWideBytes(bytes)
		if err != nil {
			return gadget, errs.WrapFailed(err, "creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}
