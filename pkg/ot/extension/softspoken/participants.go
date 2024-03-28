package softspoken

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/tmmohash"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

const transcriptLabel = "COPPER_KRYPTON_SOFTSPOKEN_OTe-"

type Receiver struct {
	ot.Participant

	Output *ot.ReceiverRotOutput // v_x ∈ [ξ][LOTe*κ]bits, the resulting OTe message (linked to sender's (v_0, v_1)).

	baseOtSeeds *ot.SenderRotOutput // k^i_0, k^i_1 ∈ [κ][2][κ]bits, the OTe seeds from a BaseOT as sender.
	xPrime      ExtPackedChoices    // x' ∈ [ξ*LOTe+σ]bits, the extended packed choice bits.
	prg         csprng.CSPRNG       // The pseudo-random generator function used for the OT expansion.
}

type Sender struct {
	ot.Participant

	Output *ot.SenderRotOutput // (v_0, v_1) ∈ [ξ][LOTe*κ]bits, the resulting OTe messages (linked to receiver's v_x).

	baseOtSeeds *ot.ReceiverRotOutput // Δ_i ∈ [κ]bits, k^i_{Δ_i} ∈ [κ][κ]bits, OTe seeds from a BaseOT as receiver.
	prg         csprng.CSPRNG         // The pseudo-random generator function used for the OT expansion.
}

// NewSoftspokenReceiver creates a `Receiver` instance for the SoftSpokenOT protocol.
// The `baseOtSeeds` are the results of playing the sender role in κ baseOTs.
func NewSoftspokenReceiver(baseParticipant types.Participant[ot.Protocol], baseOtSeeds *ot.SenderRotOutput, prg csprng.CSPRNG) (R *Receiver, err error) {
	participant, err := ot.NewParticipant(baseParticipant, transcriptLabel, 1)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid Softspoken participant input arguments")
	}
	if baseOtSeeds == nil {
		return nil, errs.NewIsNil("base OT seeds are nil")
	}
	if len(baseOtSeeds.MessagePairs) != ot.Kappa {
		return nil, errs.NewLength("base OT seeds length mismatch (should be %d, is: %d)",
			ot.Kappa, len(baseOtSeeds.MessagePairs))
	}
	for i := 0; i < ot.Kappa; i++ {
		if len(baseOtSeeds.MessagePairs[i][0]) != participant.Protocol().L() || len(baseOtSeeds.MessagePairs[i][1]) != participant.Protocol().L() {
			return nil, errs.NewLength("base OT seed[%d] message empty", i)
		}
	}
	prg, err = initialisePrg(prg, participant.SessionId())
	if err != nil {
		return nil, errs.WrapFailed(err, "Could not initialise receiver prg")
	}
	return &Receiver{
		Participant: *participant,
		Output:      &ot.ReceiverRotOutput{},
		prg:         prg,
		baseOtSeeds: baseOtSeeds,
	}, nil
}

// NewSoftspokenSender creates a `Sender` instance for the SoftSpokenOT protocol.
// The `baseOtSeeds` are the results of playing the receiver role in κ baseOTs.
func NewSoftspokenSender(baseParticipant types.Participant[ot.Protocol], baseOtSeeds *ot.ReceiverRotOutput, prg csprng.CSPRNG) (s *Sender, err error) {
	participant, err := ot.NewParticipant(baseParticipant, transcriptLabel, 2)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid softspoken participant input arguments")
	}
	if err := baseOtSeeds.Validate(participant.Protocol()); err != nil {
		return nil, errs.WrapValidation(err, "invalid base OT seeds")
	}
	prg, err = initialisePrg(prg, participant.SessionId())
	if err != nil {
		return nil, errs.WrapFailed(err, "Could not initialise sender prg")
	}
	return &Sender{
		Participant: *participant,
		baseOtSeeds: baseOtSeeds,
		Output:      &ot.SenderRotOutput{},
		prg:         prg,
	}, nil
}

func initialisePrg(prg csprng.CSPRNG, sessionId []byte) (csprng.CSPRNG, error) {
	var err error
	if prg == nil { // Default prng for DKLs24 Mult, with optimised output size.
		etaPrimeBytes := ((2 + 2) * (ot.KappaBytes + 2*SigmaBytes)) + SigmaBytes // η' = LOTe * ξ + σ = (L + ρ) * (2κ + 2s) + σ
		prg, err = tmmohash.NewTmmoPrng(ot.KappaBytes, etaPrimeBytes, nil, sessionId)
		if err != nil {
			return nil, errs.WrapFailed(err, "Could not initialise default prg")
		}
	} else {
		prg, err = prg.New(nil, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "Could not initialise custom prg")
		}
	}
	return prg, nil
}
