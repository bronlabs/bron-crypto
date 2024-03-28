package types

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

// Participant is an interface for a participant in a protocol.
type Participant[ProtocolT Protocol] interface {
	// Clone returns a deep copy of the participant.
	Clone() Participant[ProtocolT]

	// AuthKey returns the participant's authentication key.
	AuthKey() AuthKey
	// IdentityKey returns the participant's identity key.
	IdentityKey() IdentityKey

	// Prng returns the participant's pseudorandom number generator.
	Prng() io.Reader
	// Protocol returns the protocol in which the participant is participating.
	Protocol() ProtocolT
	// SessionId returns the session ID of the participant.
	SessionId() []byte
	// SetSessionId sets the session ID of the participant to the given value.
	SetSessionId(sessionId []byte)
	// Transcript returns the transcript of the participant.
	Transcript() transcripts.Transcript

	// Inialise sets the initial round number and refreshes the session ID by
	// binding it to his transcript using `dst` as domain separation tag.
	// If the participant's transcript is nil, it creates a fresh transcript.
	Initialise(initialRound int, dst string) error
	// Round returns the current round number of the participant.
	Round() int
	// NextRound sets the round number of the participant to the given value. If
	// no value is given, it sets it to participant.Round() + 1.
	NextRound(round ...int)
	// Terminate sets the round number of the participant to an arbitrary "termination" round number.
	Terminate()

	// Validate returns an error if the participant is invalid, that is, if the
	// participant's identity is not consistent with its protocol.
	Validate() error
}

type ThresholdParticipant[ProtocolT ThresholdProtocol] interface {
	Participant[ProtocolT]

	// SharingId returns the sharing ID of the participant.
	SharingId() SharingID
}
