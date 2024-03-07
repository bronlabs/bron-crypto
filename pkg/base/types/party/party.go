package types

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	t "github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

// Party is the interface for a party in any protocol.
type Party[ProtocolT t.MPCProtocol] interface {
	// Clone returns a deep copy of the party.
	Clone() Party[ProtocolT]

	// Curve returns the curve used by the protocol.
	Curve() curves.Curve
	// Prng returns the PRNG used by the party.
	Prng() io.Reader

	// Protocol returns the party's protocol configuration.
	Protocol() ProtocolT
	// SessionId returns the unique session id, framing in the CRS model any protocol run by the party.
	SessionId() []byte
	// SetSessionId sets the session id of the party.
	SetSessionId(sessionId []byte)
	// Transcript returns the transcript of messages recorded by the party.
	Transcript() transcripts.Transcript

	// Round returns the party's current round of the protocol.
	Round() int
	// InRound returns error if the party is not in the given round.
	InRound(roundNo int) error
	// NextRound sets the round to the given value. By default, it increments the round by 1.
	NextRound(roundNo ...int)
	// LastRound sets the round to an arbitrary invalid value.
	LastRound()

	// IdentityKey returns the identity key of the party, used to distinguish the party.
	IdentityKey() t.IdentityKey
	// AuthKey returns the authentication key of the party, used to authenticate the party.
	AuthKey() t.AuthKey

	// InitializeSession appends the sessionId to the transcript using `dst` as
	// domain-separation tag and extracts a fresh transcript-bound sessionId `sid`.
	// If the transcript is nil, it first creates a fresh one with `dst` as label.
	InitializeSession(dst string) error
}

// ThresholdParty is the interface for a party in a threshold protocol.
type ThresholdParty[ProtocolT t.ThresholdProtocol] interface {
	Party[ProtocolT]
	// SharingId returns the sharing id of the party, used for shamir-like sharing.
	SharingId() t.SharingID
}

// NewParty creates a new party. It only checks that the identity key is not nil.
func NewParty[ProtocolT t.MPCProtocol](prng io.Reader, protocol ProtocolT, initialRound int, sessionId []byte, transcript transcripts.Transcript, identityKey t.IdentityKey) Party[ProtocolT] {
	if identityKey == nil {
		panic("identity key cannot be nil")
	}
	return &BaseParty[ProtocolT]{
		prng:        prng,
		protocol:    protocol,
		round:       initialRound,
		sessionId:   sessionId,
		transcript:  transcript,
		identityKey: identityKey,
		sharingId:   t.SharingID(0), // invalid sharing id
	}
}

func NewThresholdParty[ProtocolT t.ThresholdProtocol](prng io.Reader, protocol ProtocolT, initialRound int, sessionId []byte, transcript transcripts.Transcript, identityKey t.IdentityKey, sharingId t.SharingID) ThresholdParty[ProtocolT] {
	if identityKey == nil {
		panic("identity key cannot be nil")
	}
	return &BaseParty[ProtocolT]{
		prng:        prng,
		protocol:    protocol,
		round:       initialRound,
		sessionId:   sessionId,
		transcript:  transcript,
		identityKey: identityKey,
		sharingId:   sharingId,
	}
}
