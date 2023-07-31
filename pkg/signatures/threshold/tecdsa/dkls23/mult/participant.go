package mult

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves/native"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/vsot"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/extension/softspoken"
	"github.com/gtank/merlin"
	"golang.org/x/crypto/sha3"
)

type Alice struct {
	prng            io.Reader
	sender          *softspoken.Sender
	Curve           *curves.Curve
	transcript      *merlin.Transcript
	uniqueSessionId []byte
	Gadget          [Zeta]curves.Scalar // Gadget (g) ∈ [ξ]ℤq is the gadget vector

	aTilde [L]curves.Scalar // ã ∈ [L]ℤq is the vector of one-time pads of Alice
	aHat   [L]curves.Scalar // â ∈ [L]ℤq is the vector of check values of Alice
	gammaA [L]curves.Scalar // γ_A ∈ [L]ℤq is the derandomization mask of Alice
}

type Bob struct {
	prng            io.Reader
	receiver        *softspoken.Receiver
	Curve           *curves.Curve
	transcript      *merlin.Transcript
	uniqueSessionId []byte
	Gadget          [Zeta]curves.Scalar // Gadget (g) ∈ [ξ]ℤq is the gadget vector

	// beta (β) ∈ [eta]bits is a vector of random bits used as input to COTe
	// This should be considered as an enum. Only one field should be used
	ForcedReuse     bool
	Beta            [EtaBytes]byte
	BetaForcedReuse [ZetaBytes]byte // EtaBytes = ZetaBytes * 1 when L = 1

	// BTilde (b̃) ∈ ℤq^L is the sum of the gadget vector elements weighted by the bits in beta
	BTilde [L]curves.Scalar

	oteReceiverOutput     *softspoken.OTeReceiverOutput
	extendedPackedChoices *softspoken.ExtPackedChoices
}

func NewAlice(curve *curves.Curve, seedOtResults *vsot.ReceiverOutput, uniqueSessionId []byte, prng io.Reader, transcript *merlin.Transcript) (*Alice, error) {
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
		transcript = merlin.NewTranscript("COPPER_DKLS_MULTIPLY-")
	}
	// TODO: parametrize forcedreuse
	sender, err := softspoken.NewCOtSender(seedOtResults, uniqueSessionId, nil, curve, true)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create sender")
	}
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId[:])
	gadget, err := generateGadgetVector(curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Alice{
		Curve:           curve,
		sender:          sender,
		transcript:      transcript,
		uniqueSessionId: uniqueSessionId,
		Gadget:          gadget,
		prng:            prng,
	}, nil
}

func NewBob(curve *curves.Curve, seedOtResults *vsot.SenderOutput, forcedReuse bool, uniqueSessionId []byte, prng io.Reader, transcript *merlin.Transcript) (*Bob, error) {
	if curve == nil {
		return nil, errs.NewInvalidArgument("curve is nil")
	}
	if prng == nil {
		return nil, errs.NewInvalidArgument("prng is nil")
	}
	if seedOtResults == nil {
		return nil, errs.NewInvalidArgument("seet ot results is nil")
	}
	// TODO: parametrize forcedreuse
	receiver, err := softspoken.NewCOtReceiver(seedOtResults, uniqueSessionId, nil, curve, true)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create receiver")
	}
	if transcript == nil {
		transcript = merlin.NewTranscript("COPPER_DKLS_MULTIPLY-")
	}
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId[:])
	gadget, err := generateGadgetVector(curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create gadget vector")
	}
	return &Bob{
		Curve:           curve,
		receiver:        receiver,
		transcript:      transcript,
		uniqueSessionId: uniqueSessionId,
		Gadget:          gadget,
		ForcedReuse:     true,
		prng:            prng,
	}, nil
}

func generateGadgetVector(curve *curves.Curve) (gadget [Zeta]curves.Scalar, err error) {
	gadget = [Zeta]curves.Scalar{}
	shake := sha3.NewCShake256(nil, []byte("COPPER_KNOX_DKLS19_MULT_GADGET_VECTOR"))
	for i := 0; i < Zeta; i++ {
		bytes := [native.FieldBytes]byte{}
		if _, err = shake.Read(bytes[:]); err != nil {
			return gadget, errs.WrapFailed(err, "could not read bytes")
		}
		gadget[i], err = curve.Scalar.SetBytes(bytes[:])
		if err != nil {
			return gadget, errs.WrapFailed(err, "creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}
