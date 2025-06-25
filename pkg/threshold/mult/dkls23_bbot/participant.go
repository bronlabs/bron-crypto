package dkls23_bbot

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_DKLS_MULTIPLY-"
	gadgetLabel     = "BRON_CRYPTO_DKLS_MULTIPLY-G-"
	aTildeLabel     = "BRON_CRYPTO_DKLS_MULTIPLY-A_TILDE-"
	thetaLabel      = "BRON_CRYPTO_DKLS_MULTIPLY-THETA-"
	muVectorLabel   = "BRON_CRYPTO_DKLS_MULTIPLY-MU_VECTOR-"
	muLabel         = "BRON_CRYPTO_DKLS_MULTIPLY-MU-"
)

var _ types.Participant = (*Alice)(nil)
var _ types.Participant = (*Bob)(nil)

type participant struct {
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.Protocol
	Round      int
	SessionId  []byte
	Tape       transcripts.Transcript
	L, Xi, Rho int

	_ ds.Incomparable
}

func (p *participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

type Alice struct {
	*participant // Base Participant

	sender *ecbbot.Sender
	g      []curves.Scalar
	alpha  [][2][]curves.Scalar
}

type Bob struct {
	*participant // Base Participant

	receiver *ecbbot.Receiver
	g        []curves.Scalar
	beta     ot.PackedBits
	gamma    [][]curves.Scalar
	// gadget   *[Xi]curves.Scalar // g ∈ [ξ]ℤq is the gadget vector
	//
	// Beta  ot.PackedBits           // β ∈ [ξ]bits is a vector of random bits used as receiver choices in OTe
	// Gamma [Xi][LOTe]curves.Scalar // γ ∈ [ξ]ℤq is the receiver output of OTe (chosen messages)
}

func newParticipant(myAuthKey types.AuthKey, protocol types.Protocol, sessionId []byte, L int, prng io.Reader, tape transcripts.Transcript, initialRound int) (*participant, error) {
	// if err := validateParticipantInputs(myAuthKey, protocol, sessionId, prng); err != nil {
	//	return nil, errs.WrapFailed(err, "invalid inputs")
	//}
	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	boundSessionId, err := tape.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	kappa := protocol.Curve().ScalarField().ElementSize() * 8
	xi := kappa + 2*base.StatisticalSecurity
	rho := utils.CeilDiv(kappa, base.ComputationalSecurity)

	return &participant{
		myAuthKey: myAuthKey,
		Prng:      prng,
		Protocol:  protocol,
		Round:     initialRound,
		SessionId: boundSessionId,
		Tape:      tape,
		L:         L,
		Xi:        xi,
		Rho:       rho,
	}, nil
}

func NewAlice(myAuthKey types.AuthKey, protocol types.Protocol, sessionId []byte, l int, prng io.Reader, transcript transcripts.Transcript) (*Alice, error) {
	p, err := newParticipant(myAuthKey, protocol, sessionId, l, prng, transcript, 2)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	sender, err := ecbbot.NewSender(myAuthKey, protocol, p.Xi, p.Rho+p.L, p.SessionId, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create sender")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Alice{
		participant: p,
		sender:      sender,
		g:           gadget,
	}, nil
}

func NewBob(myAuthKey types.AuthKey, protocol types.Protocol, sessionId []byte, l int, prng io.Reader, transcript transcripts.Transcript) (*Bob, error) {
	p, err := newParticipant(myAuthKey, protocol, sessionId, l, prng, transcript, 1)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	receiver, err := ecbbot.NewReceiver(myAuthKey, protocol, p.Xi, p.L+p.Rho, p.SessionId, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create receiver")
	}
	gadget, err := p.generateGadgetVector()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Bob{
		participant: p,
		receiver:    receiver,
		g:           gadget,
	}, nil
}

func (p *participant) generateGadgetVector() ([]curves.Scalar, error) {
	gadget := make([]curves.Scalar, p.Xi)
	for i := range gadget {
		bytes, err := p.Tape.ExtractBytes(gadgetLabel, uint(p.Protocol.Curve().ScalarField().WideElementSize()))
		if err != nil {
			return gadget, errs.WrapFailed(err, "extracting bytes from transcript")
		}
		gadget[i], err = p.Protocol.Curve().ScalarField().Element().SetBytesWide(bytes)
		if err != nil {
			return gadget, errs.WrapFailed(err, "creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}
