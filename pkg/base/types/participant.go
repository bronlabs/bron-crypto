package types

import (
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

type BaseParticipant[ProtocolT GenericProtocol] struct {
	prng       io.Reader
	protocol   ProtocolT
	round      int
	sessionId  []byte
	transcript transcripts.Transcript
	authKey    AuthKey
}

func NewBaseParticipant[ProtocolT GenericProtocol](prng io.Reader, protocol ProtocolT, initialRound int, sessionId []byte, transcript transcripts.Transcript) *BaseParticipant[ProtocolT] {
	return &BaseParticipant[ProtocolT]{
		prng:       prng,
		protocol:   protocol,
		round:      initialRound,
		sessionId:  sessionId,
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

func (b *BaseParticipant[_]) SessionId() []byte {
	return b.sessionId
}
func (b *BaseParticipant[_]) SetSessionId(sessionId []byte) {
	b.sessionId = sessionId
}

func (b *BaseParticipant[_]) Transcript() transcripts.Transcript {
	return b.transcript
}

func (b *BaseParticipant[_]) Round() int {
	return b.round
}

func (b *BaseParticipant[_]) InRound(roundNo int) error {
	if b.round != roundNo {
		return errs.NewRound("round mismatch %d != %d", b.round, roundNo)
	}
	return nil
}

func (b *BaseParticipant[_]) SetRound(roundNo int) {
	b.round = roundNo
}

func (b *BaseParticipant[_]) NextRound(step ...int) {
	if len(step) > 0 {
		b.round = step[0]
	} else {
		b.round++
	}
}

func (b *BaseParticipant[_]) LastRound() {
	b.round = -42 // Special value to indicate that the protocol is done.
}

func (b *BaseParticipant[ProtocolT]) Clone() *BaseParticipant[ProtocolT] {
	return &BaseParticipant[ProtocolT]{
		prng:       b.prng,
		protocol:   b.protocol,
		round:      b.round,
		sessionId:  slices.Clone(b.sessionId),
		transcript: b.transcript.Clone(),
	}
}
