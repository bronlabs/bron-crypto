package mult

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

type Alice struct {
	prng            io.Reader
	sender          *softspoken.Sender
	Curve           curves.Curve
	transcript      transcripts.Transcript
	uniqueSessionId []byte
	gadget          [Xi]curves.Scalar // Gadget (g) ∈ [ξ]ℤq is the gadget vector

	aTilde [L]curves.Scalar // ã ∈ [L]ℤq is the vector of one-time pads of Alice
	aHat   [L]curves.Scalar // â ∈ [L]ℤq is the vector of check values of Alice
	gammaA [L]curves.Scalar // γ_A ∈ [L]ℤq is the derandomization mask of Alice
}

type Bob struct {
	prng            io.Reader
	receiver        *softspoken.Receiver
	Curve           curves.Curve
	transcript      transcripts.Transcript
	uniqueSessionId []byte
	gadget          [Xi]curves.Scalar // Gadget (g) ∈ [ξ]ℤq is the gadget vector

	// beta (β) ∈ [eta]bits is a vector of random bits used as input to COTe
	// This should be considered as an enum. Only one field should be used
	Beta [XiBytes]byte
	// BTilde (b̃) ∈ ℤq^L is the sum of the gadget vector elements weighted by the bits in beta
	BTilde                [L]curves.Scalar
	oteReceiverOutput     *softspoken.OTeReceiverOutput
	extendedPackedChoices *softspoken.ExtPackedChoices
}

func NewAlice(curve curves.Curve, seedOtResults *vsot.ReceiverOutput, uniqueSessionId []byte, prng io.Reader, transcript transcripts.Transcript) (*Alice, error) {
	if curve == nil {
		return nil, errs.NewInvalidArgument("curve is nil")
	}
	if prng == nil {
		return nil, errs.NewInvalidArgument("prng is nil")
	}
	if seedOtResults == nil {
		return nil, errs.NewInvalidArgument("seet ot results is nil")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_DKLS_MULTIPLY-")
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	forcedReuse := true
	sender, err := softspoken.NewCOtSender(seedOtResults, uniqueSessionId, transcript, curve, forcedReuse)
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
		prng:            prng,
	}, nil
}

func NewBob(curve curves.Curve, seedOtResults *vsot.SenderOutput, uniqueSessionId []byte, prng io.Reader, transcript transcripts.Transcript) (*Bob, error) {
	if curve == nil {
		return nil, errs.NewInvalidArgument("curve is nil")
	}
	if prng == nil {
		return nil, errs.NewInvalidArgument("prng is nil")
	}
	if seedOtResults == nil {
		return nil, errs.NewInvalidArgument("seet ot results is nil")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_DKLS_MULTIPLY-")
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	forcedReuse := true
	receiver, err := softspoken.NewCOtReceiver(seedOtResults, uniqueSessionId, transcript, curve, forcedReuse)
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
		prng:            prng,
	}, nil
}

func generateGadgetVector(curve curves.Curve, transcript transcripts.Transcript) (gadget [Xi]curves.Scalar, err error) {
	gadget = [Xi]curves.Scalar{}
	transcript.AppendMessages("gadget vector", []byte("COPPER_KNOX_DKLS19_MULT_GADGET_VECTOR"))
	for i := 0; i < Xi; i++ {
		bytes := transcript.ExtractBytes("gadget", KappaBytes)
		gadget[i], err = curve.Scalar().SetBytes(bytes)
		if err != nil {
			return gadget, errs.WrapFailed(err, "creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}
