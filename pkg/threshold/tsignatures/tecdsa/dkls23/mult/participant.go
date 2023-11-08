package mult

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
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
	prng            io.Reader
	sender          *softspoken.Sender
	Curve           curves.Curve
	transcript      transcripts.Transcript
	uniqueSessionId []byte
	gadget          [][Xi]curves.Scalar // Gadget (g) ∈ [ξ]ℤq is the gadget vector

	aTilde [L]curves.Scalar // ã ∈ [L]ℤq is the vector of one-time pads of Alice
	aHat   [L]curves.Scalar // â ∈ [L]ℤq is the vector of check values of Alice
	gammaA [L]curves.Scalar // γ_A ∈ [L]ℤq is the derandomization mask of Alice

	_ types.Incomparable
}

type Bob struct {
	prng            io.Reader
	receiver        *softspoken.Receiver
	Curve           curves.Curve
	transcript      transcripts.Transcript
	uniqueSessionId []byte
	gadget          [][Xi]curves.Scalar // Gadget (g) ∈ [LOTe][ξ]ℤq is the gadget vector

	// beta (β) ∈ [ξ]bits is a vector of random bits used as input to COTe
	// This should be considered as an enum. Only one field should be used
	Beta [][XiBytes]byte
	// BTilde (b̃) ∈ ℤq^L is the sum of the gadget vector elements weighted by the bits in beta
	BTilde            [L]curves.Scalar
	oTeReceiverOutput softspoken.OTeReceiverOutput

	_ types.Incomparable
}

func NewAlice(curve curves.Curve, seedOtResults *vsot.ReceiverOutput, uniqueSessionId []byte, truePrng io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Alice, error) {
	err := validateAliceInputs(curve, seedOtResults, uniqueSessionId, truePrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid inputs")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_DKLS_MULTIPLY-", nil)
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	sender, err := softspoken.NewCOtSender(seedOtResults, uniqueSessionId, transcript, curve, true, seededPrng)
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
		prng:            truePrng,
	}, nil
}

func validateAliceInputs(curve curves.Curve, seedOtResults *vsot.ReceiverOutput, uniqueSessionId []byte, truePrng io.Reader) error {
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

func NewBob(curve curves.Curve, seedOtResults *vsot.SenderOutput, uniqueSessionId []byte, truePrng io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Bob, error) {
	err := validateBobInputs(curve, seedOtResults, uniqueSessionId, truePrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid inputs")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_DKLS_MULTIPLY-", nil)
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	receiver, err := softspoken.NewCOtReceiver(seedOtResults, uniqueSessionId, transcript, curve, true, seededPrng)
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
		prng:            truePrng,
	}, nil
}

func validateBobInputs(curve curves.Curve, seedOtResults *vsot.SenderOutput, uniqueSessionId []byte, truePrng io.Reader) error {
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

func generateGadgetVector(curve curves.Curve, transcript transcripts.Transcript) (gadget [][Xi]curves.Scalar, err error) {
	gadget = make([][Xi]curves.Scalar, 1) // LOTe = 1 for Forced Reuse
	transcript.AppendMessages("gadget vector", []byte("COPPER_KRYPTON_DKLS19_MULT_GADGET_VECTOR"))
	for i := 0; i < Xi; i++ {
		bytes, err := transcript.ExtractBytes("gadget", constants.WideFieldBytes)
		if err != nil {
			return gadget, errs.WrapFailed(err, "extracting bytes from transcript")
		}
		gadget[0][i], err = curve.Scalar().SetBytesWide(bytes)
		if err != nil {
			return gadget, errs.WrapFailed(err, "creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}
