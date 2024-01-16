package mult

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Alice struct {
	csrand          io.Reader
	sender          *softspoken.Sender
	Curve           curves.Curve
	transcript      transcripts.Transcript
	uniqueSessionId []byte
	gadget          *[Xi]curves.Scalar // (g) ∈ [ξ]ℤq is the gadget vector

	_ types.Incomparable
}

type Bob struct {
	csrand          io.Reader
	receiver        *softspoken.Receiver
	Curve           curves.Curve
	transcript      transcripts.Transcript
	uniqueSessionId []byte
	gadget          *[Xi]curves.Scalar // g ∈ [ξ]ℤq is the gadget vector

	Beta  []byte                  // β ∈ [ξ]bits is a vector of random bits used as receiver choices in OTe
	Gamma [Xi][LOTe]curves.Scalar // γ ∈ [ξ]ℤq is the receiver output of OTe (chosen messages)

	_ types.Incomparable
}

func NewAlice(curve curves.Curve, seedOtResults *vsot.ReceiverOutput, uniqueSessionId []byte, csrand io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Alice, error) {
	if err := validateParticipantInputs(curve, seedOtResults, uniqueSessionId, csrand); err != nil {
		return nil, errs.WrapFailed(err, "invalid inputs")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_DKLS_MULTIPLY-", nil)
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	sender, err := softspoken.NewCOtSender(seedOtResults, uniqueSessionId, transcript, curve, csrand, seededPrng, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create sender")
	}
	gadget, err := generateGadgetVector(curve, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Alice{
		Curve:           curve,
		sender:          sender,
		transcript:      transcript,
		uniqueSessionId: uniqueSessionId,
		gadget:          gadget,
		csrand:          csrand,
	}, nil
}

func NewBob(curve curves.Curve, seedOtResults *vsot.SenderOutput, uniqueSessionId []byte, csrand io.Reader, prgFn csprng.CSPRNG, transcript transcripts.Transcript) (*Bob, error) {
	if err := validateParticipantInputs(curve, seedOtResults, uniqueSessionId, csrand); err != nil {
		return nil, errs.WrapFailed(err, "invalid inputs")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_DKLS_MULTIPLY-", nil)
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	receiver, err := softspoken.NewCOtReceiver(seedOtResults, uniqueSessionId, transcript, curve, csrand, prgFn, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create receiver")
	}
	gadget, err := generateGadgetVector(curve, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Bob{
		Curve:           curve,
		receiver:        receiver,
		transcript:      transcript,
		uniqueSessionId: uniqueSessionId,
		gadget:          gadget,
		csrand:          csrand,
	}, nil
}

func validateParticipantInputs[T any](curve curves.Curve, seedOtResults *T, uniqueSessionId []byte, truePrng io.Reader) error {
	if curve == nil {
		return errs.NewInvalidArgument("curve is nil")
	}
	if truePrng == nil {
		return errs.NewInvalidArgument("prng is nil")
	}
	if seedOtResults == nil {
		return errs.NewInvalidArgument("seed ot results is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidArgument("unique session id is empty")
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
