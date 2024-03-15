package types

import (
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

// // Party is the interface for any kind of p in any protocol.
// type Participant[ProtocolT t.MPCProtocol] interface {
// 	// Clone returns a deep copy of the party.
// 	Clone() Party[ProtocolT]

// 	// Curve returns the curve used by the protocol.
// 	Curve() curves.Curve
// 	// Prng returns the PRNG used by the party.
// 	Prng() io.Reader

// 	// Protocol returns the party's protocol configuration.
// 	Protocol() ProtocolT
// 	// SessionId returns the unique session id, framing in the CRS model any protocol run by the party.
// 	SessionId() []byte
// 	// SetSessionId sets the session id of the party.
// 	SetSessionId(sessionId []byte)
// 	// Transcript returns the transcript of messages recorded by the party.
// 	Transcript() transcripts.Transcript

// 	// Round returns the party's current round of the protocol.
// 	Round() int
// 	// InRound returns error if the party is not in the given round.
// 	InRound(roundNo int) error
// 	// NextRound sets the round to the given value. By default, it increments the round by 1.
// 	NextRound(roundNo ...int)
// 	// LastRound sets the round to an arbitrary invalid value.
// 	LastRound()

// 	// IdentityKey returns the identity key of the party, used to distinguish the party.
// 	IdentityKey() t.IdentityKey
// 	// AuthKey returns the authentication key of the party, used to authenticate the party.
// 	AuthKey() t.AuthKey

// 	// InitializeSession appends the sessionId to the transcript using `dst` as
// 	// domain-separation tag and extracts a fresh transcript-bound sessionId `sid`.
// 	// If the transcript is nil, it first creates a fresh one with `dst` as label.
// 	InitializeSession(dst string) error
// }

// // ThresholdParty is the interface for a party in a threshold protocol.
// type ThresholdParty[ProtocolT t.ThresholdProtocol] interface {
// 	Party[ProtocolT]
// 	// SharingId returns the sharing id of the party, used for shamir-like sharing.
// 	SharingId() t.SharingID
// }

const TerminateRoundNumber = -42 // Special round number to indicate that a protocol is finished.

type BaseParticipant[ProtocolT GenericProtocol] struct {
	authKey    AuthKey
	prng       io.Reader
	protocol   ProtocolT
	Round      int
	SessionId  []byte
	transcript transcripts.Transcript

	_ ds.Incomparable
}

func NewBaseParticipant[ProtocolT MPCProtocol](prng io.Reader, protocol ProtocolT, initialRound int, sessionId []byte, transcript transcripts.Transcript) *BaseParticipant[ProtocolT] {
	return &BaseParticipant[ProtocolT]{
		prng:       prng,
		protocol:   protocol,
		Round:      initialRound,
		SessionId:  sessionId,
		transcript: transcript,
	}
}

func (b *BaseParticipant[_]) AuthKey() AuthKey {
	return b.authKey
}

func (b *BaseParticipant[_]) IdentityKey() IdentityKey {
	return b.authKey
}

func (b *BaseParticipant[_]) Curve() curves.Curve {
	return b.protocol.Curve()
}

func (b *BaseParticipant[_]) Prng() io.Reader {
	return b.prng
}

func (b *BaseParticipant[ProtocolT]) Protocol() ProtocolT {
	return b.protocol
}

func (b *BaseParticipant[_]) Transcript() transcripts.Transcript {
	return b.transcript
}

func (b *BaseParticipant[_]) Terminate() {
	b.Round = TerminateRoundNumber
}

func (b *BaseParticipant[ProtocolT]) Clone() *BaseParticipant[ProtocolT] {
	return &BaseParticipant[ProtocolT]{
		authKey:    b.authKey,
		prng:       b.prng,
		protocol:   b.protocol,
		Round:      b.Round,
		SessionId:  slices.Clone(b.SessionId),
		transcript: b.transcript.Clone(),
	}
}
