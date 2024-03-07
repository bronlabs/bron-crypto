package types

import (
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	t "github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type BaseParty[ProtocolT t.MPCProtocol] struct {
	prng       io.Reader
	protocol   ProtocolT
	round      int
	sessionId  []byte
	transcript transcripts.Transcript

	identityKey t.IdentityKey
	sharingId   t.SharingID

	_ ds.Incomparable
}

func (b *BaseParty[ProtocolT]) Clone() Party[ProtocolT] {
	return &BaseParty[ProtocolT]{
		prng:        b.prng,
		protocol:    b.protocol,
		round:       b.round,
		sessionId:   slices.Clone(b.sessionId),
		transcript:  b.transcript.Clone(),
		identityKey: b.identityKey,
	}
}

func (b *BaseParty[_]) InitializeSession(dst string) (err error) {
	if b.transcript == nil {
		b.transcript = hagrid.NewTranscript(dst, nil)
	}
	b.transcript.AppendMessages(dst, b.sessionId)
	b.sessionId, err = b.transcript.ExtractBytes(dst, base.CollisionResistanceBytes)
	if err != nil {
		return errs.WrapHashing(err, "couldn't extract sessionId from transcript")
	}
	return nil
}

func (b *BaseParty[_]) Curve() curves.Curve {
	return b.protocol.Curve()
}

func (b *BaseParty[_]) Prng() io.Reader {
	return b.prng
}

func (b *BaseParty[ProtocolT]) Protocol() ProtocolT {
	return b.protocol
}

func (b *BaseParty[_]) SessionId() []byte {
	return b.sessionId
}
func (b *BaseParty[_]) SetSessionId(sessionId []byte) {
	b.sessionId = sessionId
}

func (b *BaseParty[_]) SharingId() t.SharingID {
	return b.sharingId
}

func (b *BaseParty[_]) Transcript() transcripts.Transcript {
	return b.transcript
}

func (b *BaseParty[_]) IdentityKey() t.IdentityKey {
	return b.identityKey
}

func (b *BaseParty[_]) AuthKey() t.AuthKey {
	authKey, ok := b.identityKey.(t.AuthKey)
	if !ok {
		panic("identity key is not an authentication key")
	}
	return authKey
}

func (b *BaseParty[_]) Round() int {
	return b.round
}
func (b *BaseParty[_]) SetRound(roundNo int) {
	b.round = roundNo
}
func (b *BaseParty[_]) InRound(roundNo int) error {
	if b.round != roundNo {
		return errs.NewRound("round mismatch %d != %d", b.round, roundNo)
	}
	return nil
}
func (b *BaseParty[_]) NextRound(step ...int) {
	if len(step) > 0 {
		b.round = step[0]
	} else {
		b.round++
	}
}
func (b *BaseParty[_]) LastRound() {
	b.round = -42 // Special value to indicate that the protocol is done.
}
