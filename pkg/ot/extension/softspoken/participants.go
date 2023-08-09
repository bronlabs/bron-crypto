package softspoken

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

type Receiver struct {
	// baseOtSeeds (k^i_0, k^i_1) ∈ [κ][2][κ]bits are the options used while
	//  of playing the sender in a base OT protocol. They act as seeds to COTe.
	baseOtSeeds *vsot.SenderOutput

	// extPackedChoices (x_i ∈ [η']bits) are the extended packed choices of the receiver.
	extPackedChoices ExtPackedChoices

	// sid is the unique identifier of the current session (sid in DKLs19)
	sid []byte

	// transcript is the transcript containing the protocol's publicly exchanged messages.
	transcript transcripts.Transcript

	// curve is the elliptic curve used in the protocol.
	curve *curves.Curve

	// useForcedReuse is a flag that indicates whether the protocol should use forced reuse.
	useForcedReuse bool
}

type Sender struct {
	// baseOtSeeds (Δ_i ∈ [κ]bits, k^i_{Δ_i} ∈ [κ][κ]bits) are the results
	// of playing the receiver in a base OT protocol. They act as seeds of COTe.
	baseOtSeeds *vsot.ReceiverOutput

	// sid is the unique identifier of the current session (sid in DKLs19)
	sid []byte

	// transcript is the transcript containing the protocol's publicly exchanged messages.
	transcript transcripts.Transcript

	// curve is the elliptic curve used in the protocol.
	curve *curves.Curve

	// useForcedReuse is a flag that indicates whether the protocol should use forced reuse.
	useForcedReuse bool
}

// NewCOtReceiver creates a `Receiver` instance for the SoftSpokenOT protocol.
// The `baseOtResults` are the results of playing the sender role in κ baseOTs.
func NewCOtReceiver(
	baseOtResults *vsot.SenderOutput,
	uniqueSessionId []byte,
	transcript transcripts.Transcript,
	curve *curves.Curve,
	useForcedReuse bool,
) (*Receiver, error) {
	if transcript == nil {
		transcript = merlin.NewTranscript("KNOX_PRIMITIVES_SOFTSPOKEN_COTe")
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	return &Receiver{
		baseOtSeeds:    baseOtResults,
		sid:            uniqueSessionId,
		transcript:     transcript,
		curve:          curve,
		useForcedReuse: useForcedReuse,
	}, nil
}

// NewCOtSender creates a `Sender` instance for the SoftSpokenOT protocol.
// The `baseOtResults` are the results of playing the receiver role in κ baseOTs.
func NewCOtSender(
	baseOtResults *vsot.ReceiverOutput,
	uniqueSessionId []byte,
	transcript transcripts.Transcript,
	curve *curves.Curve,
	useForcedReuse bool,
) (*Sender, error) {
	if transcript == nil {
		transcript = merlin.NewTranscript("KNOX_PRIMITIVES_SOFTSPOKEN_COTe")
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	return &Sender{
		baseOtSeeds:    baseOtResults,
		sid:            uniqueSessionId,
		transcript:     transcript,
		curve:          curve,
		useForcedReuse: useForcedReuse,
	}, nil
}
