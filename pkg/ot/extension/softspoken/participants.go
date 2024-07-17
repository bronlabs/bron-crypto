package softspoken

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/tmmohash"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
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
func NewSoftspokenReceiver(myAuthKey types.AuthKey, protocol types.Protocol, baseOtSeeds *ot.SenderRotOutput, sessionId []byte, transcript transcripts.Transcript,
	csrand io.Reader, prg csprng.CSPRNG, lOTe, Xi int,
) (R *Receiver, err error) {
	participant, err := ot.NewParticipant(myAuthKey, protocol, Xi, lOTe, sessionId, transcriptLabel, transcript, csrand, 1)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid COTe participant input arguments")
	}
	if baseOtSeeds == nil {
		return nil, errs.NewIsNil("base OT seeds are nil")
	}
	if len(baseOtSeeds.MessagePairs) != ot.Kappa {
		return nil, errs.NewLength("base OT seeds length mismatch (should be %d, is: %d)",
			ot.Kappa, len(baseOtSeeds.MessagePairs))
	}
	for i := 0; i < ot.Kappa; i++ {
		if len(baseOtSeeds.MessagePairs[i][0]) == 0 || len(baseOtSeeds.MessagePairs[i][1]) == 0 {
			return nil, errs.NewLength("base OT seed[%d] message empty", i)
		}
	}
	prg, err = initialisePrg(prg, sessionId)
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
func NewSoftspokenSender(myAuthKey types.AuthKey, protocol types.Protocol, baseOtSeeds *ot.ReceiverRotOutput, sessionId []byte, transcript transcripts.Transcript,
	csrand io.Reader, prg csprng.CSPRNG, lOTe, Xi int,
) (s *Sender, err error) {
	participant, err := ot.NewParticipant(myAuthKey, protocol, Xi, lOTe, sessionId, transcriptLabel, transcript, csrand, 2)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid COTe participant input arguments")
	}
	if baseOtSeeds == nil {
		return nil, errs.NewIsNil("base OT seeds are nil")
	}
	if len(baseOtSeeds.ChosenMessages) != ot.Kappa || len(baseOtSeeds.Choices) != ot.KappaBytes {
		return nil, errs.NewLength("base OT seeds length mismatch (should be %d,%d; is: %d,%d)",
			ot.Kappa, ot.KappaBytes, len(baseOtSeeds.ChosenMessages), len(baseOtSeeds.Choices))
	}
	for i := 0; i < ot.Kappa; i++ {
		if len(baseOtSeeds.ChosenMessages[i]) == 0 {
			return nil, errs.NewLength("base OT seed[%d] chosen message empty", i)
		}
	}
	prg, err = initialisePrg(prg, sessionId)
	if err != nil {
		return nil, errs.WrapFailed(err, "Could not initialise sender prg")
	}
	return &Sender{
		baseOtSeeds: baseOtSeeds,
		Output:      &ot.SenderRotOutput{},
		prg:         prg,
		Participant: *participant,
	}, nil
}

func initialisePrg(prg csprng.CSPRNG, sessionId []byte) (csprng.CSPRNG, error) {
	var err error
	if prg == nil { // Default prng for DKLs23 Mult, with optimised output size.
		etaPrimeBytes := ((2 + 2) * (ot.KappaBytes + 2*SigmaBytes)) + SigmaBytes // η' = LOTe * ξ + σ = (L + ρ) * (2κ + 2s) + σ
		prg, err = tmmohash.NewTmmoPrng(ot.KappaBytes, etaPrimeBytes, nil, sessionId)
		if err != nil {
			return nil, errs.WrapFailed(err, "Could not initialise prg")
		}
	} else {
		prg, err = prg.New(nil, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "Could not initialise prg")
		}
	}
	return prg, nil
}

func sendTo[M any](p2p chan<- ds.Map[types.IdentityKey, M], destination types.IdentityKey, m M) {
	p2pMessage := hashmap.NewHashableHashMap[types.IdentityKey, M]()
	p2pMessage.Put(destination, m)
	p2p <- p2pMessage
}

func receiveFrom[M any](p2p <-chan ds.Map[types.IdentityKey, M], source types.IdentityKey) (M, error) {
	p2pMessage := <-p2p
	m, ok := p2pMessage.Get(source)
	if !ok {
		return *new(M), errs.NewFailed("no message")
	}
	return m, nil
}

func (s *Sender) Run(router roundbased.MessageRouter, receiver *Receiver) (oTeSenderOutput [][2][][16]byte, err error) {
	me := s.IdentityKey()
	her := receiver.IdentityKey()
	r1 := roundbased.NewUnicastRound[*Round1Output](me, 1, router)

	r2In, err := receiveFrom(r1.UnicastIn(), her)
	if err != nil {
		return nil, errs.WrapFailed(err, "round 2 failed")
	}
	r2Out, err := s.Round2(r2In)
	if err != nil {
		return nil, errs.WrapFailed(err, "round 2 failed")
	}
	return r2Out, nil
}

func (r *Receiver) Run(router roundbased.MessageRouter, sender *Sender, x bitstring.PackedBits) (oTeReceiverOutput [][][16]byte, err error) {
	me := r.IdentityKey()
	her := sender.IdentityKey()
	r1 := roundbased.NewUnicastRound[*Round1Output](me, 1, router)

	oTeReceiverOutput, r1Out, err := r.Round1(x)
	if err != nil {
		return nil, errs.WrapFailed(err, "round 1 failed")
	}
	sendTo(r1.UnicastOut(), her, r1Out)
	return oTeReceiverOutput, nil
}
