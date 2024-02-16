package mult

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_DKLS_MULTIPLY-"

var _ types.GenericParticipant = (*Alice)(nil)
var _ types.GenericParticipant = (*Bob)(nil)

type Alice struct {
	csrand     io.Reader
	sender     *softspoken.Sender
	Curve      curves.Curve
	transcript transcripts.Transcript
	sessionId  []byte
	gadget     *[Xi]curves.Scalar // (g) ∈ [ξ]ℤq is the gadget vector

	_ ds.Incomparable
}

type Bob struct {
	csrand     io.Reader
	receiver   *softspoken.Receiver
	Curve      curves.Curve
	transcript transcripts.Transcript
	sessionId  []byte
	gadget     *[Xi]curves.Scalar // g ∈ [ξ]ℤq is the gadget vector

	Beta  []byte                  // β ∈ [ξ]bits is a vector of random bits used as receiver choices in OTe
	Gamma [Xi][LOTe]curves.Scalar // γ ∈ [ξ]ℤq is the receiver output of OTe (chosen messages)

	_ ds.Incomparable
}

func NewAlice(curve curves.Curve, seedOtResults *ot.ReceiverRotOutput, sessionId []byte, csrand io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Alice, error) {
	if err := validateParticipantInputs(curve, seedOtResults, sessionId, csrand); err != nil {
		return nil, errs.WrapFailed(err, "invalid inputs")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, curve.Name())
	transcript, sessionId, err := hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sender, err := softspoken.NewSoftspokenSender(seedOtResults, sessionId, transcript, curve, csrand, seededPrng, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create sender")
	}
	gadget, err := generateGadgetVector(curve, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Alice{
		Curve:      curve,
		sender:     sender,
		transcript: transcript,
		sessionId:  sessionId,
		gadget:     gadget,
		csrand:     csrand,
	}, nil
}

func NewBob(curve curves.Curve, seedOtResults *ot.SenderRotOutput, sessionId []byte, csrand io.Reader, prgFn csprng.CSPRNG, transcript transcripts.Transcript) (*Bob, error) {
	if err := validateParticipantInputs(curve, seedOtResults, sessionId, csrand); err != nil {
		return nil, errs.WrapFailed(err, "invalid inputs")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, curve.Name())
	transcript, sessionId, err := hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	receiver, err := softspoken.NewSoftspokenReceiver(seedOtResults, sessionId, transcript, curve, csrand, prgFn, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create receiver")
	}
	gadget, err := generateGadgetVector(curve, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Bob{
		Curve:      curve,
		receiver:   receiver,
		transcript: transcript,
		sessionId:  sessionId,
		gadget:     gadget,
		csrand:     csrand,
	}, nil
}

func validateParticipantInputs[T any](curve curves.Curve, seedOtResults *T, sessionId []byte, truePrng io.Reader) error {
	if curve == nil {
		return errs.NewArgument("curve is nil")
	}
	if truePrng == nil {
		return errs.NewArgument("prng is nil")
	}
	if seedOtResults == nil {
		return errs.NewArgument("seed ot results is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewArgument("unique session id is empty")
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
		gadget[i], err = curve.Scalar().SetBytesWide(bytes)
		if err != nil {
			return gadget, errs.WrapFailed(err, "creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}
