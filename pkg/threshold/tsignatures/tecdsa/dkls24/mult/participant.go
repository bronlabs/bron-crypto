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
	*types.BaseParticipant[types.GenericProtocol]

	sender *softspoken.Sender
	gadget *[Xi]curves.Scalar // (g) ∈ [ξ]ℤq is the gadget vector

	_ ds.Incomparable
}

type Bob struct {
	*types.BaseParticipant[types.GenericProtocol]

	receiver *softspoken.Receiver
	gadget   *[Xi]curves.Scalar // g ∈ [ξ]ℤq is the gadget vector

	Beta  []byte                  // β ∈ [ξ]bits is a vector of random bits used as receiver choices in OTe
	Gamma [Xi][LOTe]curves.Scalar // γ ∈ [ξ]ℤq is the receiver output of OTe (chosen messages)

	_ ds.Incomparable
}

func NewParticipant[T any](curve curves.Curve, seedOtResults *T, sessionId []byte, csrand io.Reader, prgFn csprng.CSPRNG, transcript transcripts.Transcript, roundNo int) (participant *types.BaseParticipant[types.GenericProtocol], gadget *[Xi]curves.Scalar, err error) {
	if err := validateParticipantInputs(curve, seedOtResults, sessionId, csrand); err != nil {
		return nil, nil, errs.WrapFailed(err, "invalid inputs")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, curve.Name())
	transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	gadget, err = generateGadgetVector(curve, transcript)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	protocol, err := types.NewGenericProtocol(curve)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create protocol")
	}

	return types.NewBaseParticipant(csrand, protocol, roundNo, sessionId, transcript), gadget, nil
}

func NewAlice(curve curves.Curve, seedOtResults *ot.ReceiverRotOutput, sessionId []byte, csrand io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Alice, error) {
	participant, gadget, err := NewParticipant(curve, seedOtResults, sessionId, csrand, seededPrng, transcript, 2)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	sender, err := softspoken.NewSoftspokenSender(seedOtResults, sessionId, transcript, curve, csrand, seededPrng, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create sender")
	}
	return &Alice{
		BaseParticipant: participant,
		sender:          sender,
		gadget:          gadget,
	}, nil
}

func NewBob(curve curves.Curve, seedOtResults *ot.SenderRotOutput, sessionId []byte, csrand io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Bob, error) {
	participant, gadget, err := NewParticipant(curve, seedOtResults, sessionId, csrand, seededPrng, transcript, 2)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	receiver, err := softspoken.NewSoftspokenReceiver(seedOtResults, sessionId, transcript, curve, csrand, seededPrng, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create receiver")
	}
	return &Bob{
		BaseParticipant: participant,
		receiver:        receiver,
		gadget:          gadget,
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
