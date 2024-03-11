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

var _ types.MPCParticipant = (*Alice)(nil)
var _ types.MPCParticipant = (*Bob)(nil)

type Alice struct {
	*types.BaseParticipant[types.MPCProtocol]

	sender *softspoken.Sender
	gadget *[Xi]curves.Scalar // (g) ∈ [ξ]ℤq is the gadget vector

	_ ds.Incomparable
}
type Bob struct {
	*types.BaseParticipant[types.MPCProtocol]

	receiver *softspoken.Receiver
	gadget   *[Xi]curves.Scalar // g ∈ [ξ]ℤq is the gadget vector

	Beta  []byte                  // β ∈ [ξ]bits is a vector of random bits used as receiver choices in OTe
	Gamma [Xi][LOTe]curves.Scalar // γ ∈ [ξ]ℤq is the receiver output of OTe (chosen messages)

	_ ds.Incomparable
}

func NewParticipant[T any](myAuthKey types.AuthKey, protocol types.MPCProtocol, seedOtResults *T, sessionId []byte, csrand io.Reader, prgFn csprng.CSPRNG, transcript transcripts.Transcript, roundNo int) (participant *types.BaseParticipant[types.MPCProtocol], gadget *[Xi]curves.Scalar, err error) {
	if err := validateParticipantInputs(myAuthKey, protocol, seedOtResults, sessionId, csrand); err != nil {
		return nil, nil, errs.WrapFailed(err, "invalid inputs")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}
	gadget, err = generateGadgetVector(protocol.Curve(), transcript)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return types.NewBaseParticipant(csrand, protocol, roundNo, sessionId, transcript), gadget, nil
}

func NewAlice(myAuthKey types.AuthKey, protocol types.MPCProtocol, seedOtResults *ot.ReceiverRotOutput, sessionId []byte, csrand io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Alice, error) {
	participant, gadget, err := NewParticipant(myAuthKey, protocol, seedOtResults, sessionId, csrand, seededPrng, transcript, 1)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	sender, err := softspoken.NewSoftspokenSender(myAuthKey, protocol, seedOtResults, sessionId, transcript, csrand, seededPrng, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create sender")
	}
	return &Alice{
		BaseParticipant: participant,
		sender:          sender,
		gadget:          gadget,
	}, nil
}

func NewBob(myAuthKey types.AuthKey, protocol types.MPCProtocol, seedOtResults *ot.SenderRotOutput, sessionId []byte, csrand io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Bob, error) {
	participant, gadget, err := NewParticipant(myAuthKey, protocol, seedOtResults, sessionId, csrand, seededPrng, transcript, 1)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create participant / gadget vector")
	}
	receiver, err := softspoken.NewSoftspokenReceiver(myAuthKey, protocol, seedOtResults, sessionId, transcript, csrand, seededPrng, LOTe, Xi)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create receiver")
	}
	return &Bob{
		BaseParticipant: participant,
		receiver:        receiver,
		gadget:          gadget,
	}, nil
}

func validateParticipantInputs[T any](myIdentityKey types.IdentityKey, protocol types.MPCProtocol, seedOtResults *T, sessionId []byte, truePrng io.Reader) error {
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
	if err := types.ValidateMPCProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "mpc protocol config")
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
