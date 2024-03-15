package types

import (
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

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
