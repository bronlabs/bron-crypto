package softspoken

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/tmmohash"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Receiver struct {
	baseOtSeeds       *vsot.SenderOutput // k^i_0, k^i_1 ∈ [κ][2][κ]bits, the OTe seeds from a BaseOT as sender.
	extPackedChoices  ExtPackedChoices   // x_i ∈ [η']bits, the extended packed choice bits.
	oTeReceiverOutput OTeMessage         // v_x ∈ [LOTe][ξ][κ]bits, the resulting OTe message (linked to sender's {v_0, v_1}).

	useForcedReuse bool // indicates whether the protocol should use forced reuse.

	sid        []byte                 // Unique identifier of the current session (sid in DKLs19)
	transcript transcripts.Transcript // Transcript containing the protocol's publicly exchanged messages.
	curve      curves.Curve           // The elliptic curve used in the protocol.
	prg        csprng.CSPRNG          // The pseudo-random generator function used for the OT expansion.
	csrand     io.Reader              // A true randomness source.

	_ types.Incomparable
}

type Sender struct {
	baseOtSeeds *vsot.ReceiverOutput // Δ_i ∈ [κ]bits, k^i_{Δ_i} ∈ [κ][κ]bits, OTe seeds from a BaseOT as receiver.

	useForcedReuse bool // indicates whether the protocol should use forced reuse.

	sid        []byte                 // Unique identifier of the current session (sid in DKLs19)
	transcript transcripts.Transcript // Transcript containing the protocol's publicly exchanged messages.
	curve      curves.Curve           // The elliptic curve used in the protocol.
	prg        csprng.CSPRNG          // The pseudo-random generator function used for the OT expansion.
	csrand     io.Reader              // A true randomness source.
	_          types.Incomparable
}

// NewCOtReceiver creates a `Receiver` instance for the SoftSpokenOT protocol.
// The `baseOtSeeds` are the results of playing the sender role in κ baseOTs.
func NewCOtReceiver(baseOtSeeds *vsot.SenderOutput, sid []byte, transcript transcripts.Transcript, curve curves.Curve, csrand io.Reader, useForcedReuse bool, prgFn csprng.CSPRNG,
) (R *Receiver, err error) {
	if err = validateParticipantInputs(baseOtSeeds, sid, curve, csrand); err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid COTe participant input arguments")
	}
	t, prg, err := setDefaultInputs(transcript, sid, prgFn)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not set default inputs")
	}
	return &Receiver{
		baseOtSeeds:    baseOtSeeds,
		sid:            sid,
		transcript:     t,
		curve:          curve,
		useForcedReuse: useForcedReuse,
		prg:            prg,
		csrand:         csrand,
	}, nil
}

// NewCOtSender creates a `Sender` instance for the SoftSpokenOT protocol.
// The `baseOtSeeds` are the results of playing the receiver role in κ baseOTs.
func NewCOtSender(baseOtSeeds *vsot.ReceiverOutput, sid []byte, transcript transcripts.Transcript, curve curves.Curve, csrand io.Reader, useForcedReuse bool, prgFn csprng.CSPRNG,
) (s *Sender, err error) {
	if err = validateParticipantInputs(baseOtSeeds, sid, curve, csrand); err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid COTe participant input arguments")
	}
	t, prg, err := setDefaultInputs(transcript, sid, prgFn)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not set default inputs")
	}
	return &Sender{
		baseOtSeeds:    baseOtSeeds,
		sid:            sid,
		transcript:     t,
		curve:          curve,
		useForcedReuse: useForcedReuse,
		prg:            prg,
		csrand:         csrand,
	}, nil
}

func validateParticipantInputs[T any](baseOtSeeds *T, sid []byte, curve curves.Curve, rand io.Reader) (err error) {
	if baseOtSeeds == nil {
		return errs.NewIsNil("base OT seeds are nil")
	}
	if len(sid) == 0 {
		return errs.NewIsNil("unique session id is empty")
	}
	if curve == nil {
		return errs.NewIsNil("curve is nil")
	}
	if rand == nil {
		return errs.NewIsNil("rand is nil")
	}
	return nil
}

func setDefaultInputs(transcript transcripts.Transcript, sid []byte, prgFn csprng.CSPRNG) (t transcripts.Transcript, prg csprng.CSPRNG, err error) {
	if transcript == nil {
		t = hagrid.NewTranscript("KRYPTON_PRIMITIVES_SOFTSPOKEN_COTe", nil)
	} else {
		t = transcript
	}
	t.AppendMessages("session_id", sid)
	if prgFn == nil { // Default prng output size optimised for DKLs23 Mult.
		etaPrimeBytes := (1 * XiBytes) + SigmaBytes // η' = LOTe*ξ + σ with LOTe = 1
		prgFn, err = tmmohash.NewTmmoPrng(KappaBytes, etaPrimeBytes, nil, sid)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "Could not initialise prg")
		}
	} else {
		prgFn, err = prgFn.New(nil, nil)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "Could not initialise prg")
		}
	}
	return t, prgFn, nil
}
