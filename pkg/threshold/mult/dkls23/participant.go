package dkls23

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_DKLS_MULTIPLY-"

var _ types.Participant = (*Alice)(nil)
var _ types.Participant = (*Bob)(nil)

type participant struct {
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.Protocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	_ ds.Incomparable
}

func (p *participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

type Alice struct {
	*participant // Base Participant

	sender *softspoken.Sender
	gadget *[Xi]curves.Scalar // (g) ∈ [ξ]ℤq is the gadget vector

	_ ds.Incomparable
}

type Bob struct {
	*participant // Base Participant

	receiver *softspoken.Receiver
	gadget   *[Xi]curves.Scalar // g ∈ [ξ]ℤq is the gadget vector

	Beta  ot.PackedBits           // β ∈ [ξ]bits is a vector of random bits used as receiver choices in OTe
	Gamma [Xi][LOTe]curves.Scalar // γ ∈ [ξ]ℤq is the receiver output of OTe (chosen messages)

	_ ds.Incomparable
}

func newParticipant[T any](myAuthKey types.AuthKey, protocol types.Protocol, seedOtResults *T, sessionId []byte, csrand io.Reader, transcript transcripts.Transcript, initialRound int) (*participant, error) {
	if err := validateParticipantInputs[T](myAuthKey, protocol, seedOtResults, sessionId, csrand); err != nil {
		return nil, errs.WrapFailed(err, "invalid inputs")
	}
	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, csrand)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}
	return &participant{
		myAuthKey:  myAuthKey,
		Prng:       csrand,
		Protocol:   protocol,
		Round:      initialRound,
		SessionId:  boundSessionId,
		Transcript: transcript,
	}, nil
}

func NewAlice(myAuthKey types.AuthKey, protocol types.Protocol, seedOtResults *ot.ReceiverRotOutput, sessionId []byte, csrand io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Alice, error) {
	participant, err := newParticipant(myAuthKey, protocol, seedOtResults, sessionId, csrand, transcript, 2)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	sender, err := softspoken.NewSoftspokenSender(myAuthKey, protocol, seedOtResults, sessionId, transcript, csrand, seededPrng, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create sender")
	}
	gadget, err := generateGadgetVector(protocol.Curve(), sender.Transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Alice{
		participant: participant,
		sender:      sender,
		gadget:      gadget,
	}, nil
}

func NewBob(myAuthKey types.AuthKey, protocol types.Protocol, seedOtResults *ot.SenderRotOutput, sessionId []byte, csrand io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Bob, error) {
	participant, err := newParticipant(myAuthKey, protocol, seedOtResults, sessionId, csrand, transcript, 1)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	receiver, err := softspoken.NewSoftspokenReceiver(myAuthKey, protocol, seedOtResults, sessionId, transcript, csrand, seededPrng, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create receiver")
	}
	gadget, err := generateGadgetVector(protocol.Curve(), receiver.Transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Bob{
		participant: participant,
		receiver:    receiver,
		gadget:      gadget,
	}, nil
}

func validateParticipantInputs[T any](myIdentityKey types.IdentityKey, protocol types.Protocol, seedOtResults *T, sessionId []byte, truePrng io.Reader) error {
	if truePrng == nil {
		return errs.NewArgument("prng is nil")
	}
	if seedOtResults == nil {
		return errs.NewArgument("seed ot results is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewArgument("unique session id is empty")
	}
	if err := types.ValidateIdentityKey(myIdentityKey); err != nil {
		return errs.WrapValidation(err, "identity key")
	}
	if err := types.ValidateProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	return nil
}

func generateGadgetVector(curve curves.Curve, transcript transcripts.Transcript) (gadget *[Xi]curves.Scalar, err error) {
	gadget = new([Xi]curves.Scalar)
	transcript.AppendMessages("gadget vector", []byte("COPPER_KRYPTON_DKLS19_MULT_GADGET_VECTOR"))
	for i := 0; i < Xi; i++ {
		bytes, err := transcript.ExtractBytes("gadget", base.WideFieldBytes)
		if err != nil {
			return gadget, errs.WrapFailed(err, "extracting bytes from transcript")
		}
		gadget[i], err = curve.ScalarField().Element().SetBytesWide(bytes)
		if err != nil {
			return gadget, errs.WrapFailed(err, "creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}

func (b *Bob) Run(router roundbased.MessageRouter, a *Alice, aliceInput [2]curves.Scalar) (Round1Scalar curves.Scalar, Round2Scalar, Round3Scalar *OutputShares, err error) {
	bob := b.IdentityKey()
	alice := a.IdentityKey()
	r1 := roundbased.NewBroadcastRound[*Round1Output](bob, 1, router)
	r2 := roundbased.NewBroadcastRound[*Round2Output](alice, 2, router)

	// Round 1
	r1Scalar, r1Out, err := b.Round1()
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "round 1 failed")
	}
	r1.BroadcastOut() <- r1Out

	// Round 2
	r2Scalar, r2Out, err := a.Round2(r1Out, aliceInput)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "round 2 failed")
	}
	r2.BroadcastOut() <- r2Out

	// Round 3
	r3Scalar, err := b.Round3(r2Out)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "round 3 failed")
	}
	return r1Scalar, r2Scalar, r3Scalar, err
}
