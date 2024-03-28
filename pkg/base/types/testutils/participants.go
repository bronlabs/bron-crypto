package testutils

import (
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const TerminateRoundNumber = -42 // Special round number to indicate that a protocol is finished.

type BaseParticipant[ProtocolT types.Protocol] struct {
	authKey    types.AuthKey
	prng       io.Reader
	protocol   ProtocolT
	round      int
	sessionId  []byte
	transcript transcripts.Transcript

	_ ds.Incomparable
}

func NewParticipant[ProtocolT types.Protocol](authKey types.AuthKey, prng io.Reader, protocol ProtocolT, initialRound int, sessionId []byte, transcript transcripts.Transcript) (p types.Participant[ProtocolT], err error) {
	p = &BaseParticipant[ProtocolT]{
		authKey:    authKey,
		prng:       prng,
		protocol:   protocol,
		round:      initialRound,
		sessionId:  sessionId,
		transcript: transcript,
	}
	if err := p.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "invalid base participant")
	}
	return p, nil
}

func (cp *BaseParticipant[_]) Validate() error {
	if err := types.ValidateAuthKey(cp.authKey); err != nil {
		return errs.WrapValidation(err, "invalid auth key")
	}
	if !cp.protocol.Participants().Contains(cp.authKey) {
		return errs.NewMissing("participant is not included in the protocol")
	}
	return nil
}

func (cp *BaseParticipant[ProtocolT]) Clone() types.Participant[ProtocolT] {
	return &BaseParticipant[ProtocolT]{
		authKey:    cp.authKey,
		prng:       cp.prng,
		protocol:   cp.protocol,
		round:      cp.round,
		sessionId:  slices.Clone(cp.SessionId()),
		transcript: cp.transcript.Clone(),
	}
}

func (cp *BaseParticipant[_]) AuthKey() types.AuthKey {
	return cp.authKey
}

func (cp *BaseParticipant[_]) IdentityKey() types.IdentityKey {
	return cp.authKey
}

func (cp *BaseParticipant[_]) Initialise(initialRound int, dst string) (err error) {
	if cp.transcript == nil {
		cp.transcript = hagrid.NewTranscript(dst, nil)
	}
	cp.transcript.AppendMessages(dst, cp.sessionId)
	cp.sessionId, err = cp.transcript.ExtractBytes(dst, base.CollisionResistance)
	if err != nil {
		return errs.WrapHashing(err, "couldn't extract sessionId from transcript")
	}
	cp.round = initialRound
	return nil
}

func (cp *BaseParticipant[_]) Prng() io.Reader {
	return cp.prng
}

func (cp *BaseParticipant[ProtocolT]) Protocol() ProtocolT {
	return cp.protocol
}

func (cp *BaseParticipant[_]) Round() int {
	return cp.round
}

func (cp *BaseParticipant[_]) NextRound(round ...int) {
	if len(round) > 0 {
		cp.round = round[0]
	} else {
		cp.NextRound()
	}
}

func (cp *BaseParticipant[_]) SessionId() []byte {
	return cp.sessionId
}

func (cp *BaseParticipant[_]) SetSessionId(sessionId []byte) {
	cp.sessionId = sessionId
}

func (cp *BaseParticipant[_]) Transcript() transcripts.Transcript {
	return cp.transcript
}

func (cp *BaseParticipant[_]) Terminate() {
	cp.round = TerminateRoundNumber
}

/*.------------------------------ Threshold ---------------------------------.*/

type BaseThresholdParticipant[ProtocolT types.ThresholdProtocol] struct {
	BaseParticipant[ProtocolT]
	sharingId types.SharingID
}

func NewThresholdParticipant[ProtocolT types.ThresholdProtocol](authKey types.AuthKey, prng io.Reader, protocol ProtocolT, initialRound int, sessionId []byte, transcript transcripts.Transcript, sharingId types.SharingID) (ctp types.ThresholdParticipant[ProtocolT], err error) {
	ctp = &BaseThresholdParticipant[ProtocolT]{
		BaseParticipant: BaseParticipant[ProtocolT]{
			authKey:    authKey,
			prng:       prng,
			protocol:   protocol,
			round:      initialRound,
			sessionId:  sessionId,
			transcript: transcript,
		},
		sharingId: sharingId,
	}
	if err := ctp.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "invalid threshold base participant")
	}
	return ctp, nil
}

func (tbp *BaseThresholdParticipant[_]) Validate() error {
	if err := tbp.BaseParticipant.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid base participant")
	}
	if tbp.SharingId() <= 0 {
		return errs.NewValue("sharing id must be a positive number")
	}
	mySharingId, exists := types.DeriveSharingConfig(tbp.protocol.Participants()).Reverse().Get(tbp.IdentityKey())
	if !exists {
		return errs.NewMissing("my sharing id couldn't be computed from the protocol config")
	}
	if mySharingId != tbp.SharingId() {
		return errs.NewValue("sharing id (%d) != what it should be (%d)", tbp.SharingId(), mySharingId)
	}
	return nil
}

func (p *BaseThresholdParticipant[_]) SharingId() types.SharingID {
	return p.sharingId
}

/*.--------------------------------------------------------------------------.*/
/*.--------------------------------------------------------------------------.*/

func MakeParticipants[ProtocolT types.Protocol](protocol ProtocolT, prng io.Reader, sessionId []byte) ([]types.Participant[ProtocolT], error) {
	participants := make([]types.Participant[ProtocolT], protocol.Participants().Size())
	for i, idKey := range protocol.Participants().List() {
		authKey, ok := idKey.(types.AuthKey)
		if !ok {
			return nil, errs.NewType("participantId #%d is not an AuthKey: %s", i, idKey.String())
		}
		participant, err := NewParticipant(authKey, prng, protocol, 0, slices.Clone(sessionId), hagrid.NewTranscript("test", nil))
		if err != nil {
			return nil, errs.WrapFailed(err, "participant creation")
		}
		participants[i] = participant
	}
	return participants, nil
}

func MakeThresholdParticipants[ProtocolT types.ThresholdProtocol](n int, cipherSuite types.SigningSuite, prng io.Reader, protocol ProtocolT, initialRound int, sessionId []byte, transcript transcripts.Transcript, sharingConfig types.SharingConfig) ([]types.ThresholdParticipant[ProtocolT], error) {
	authKeys, err := MakeTestAuthKeys(cipherSuite, n)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make auth keys")
	}
	participants := make([]types.ThresholdParticipant[ProtocolT], len(authKeys))
	for i, authKey := range authKeys {
		sharingId, exists := sharingConfig.Reverse().Get(authKey)
		if !exists {
			return nil, errs.NewMissing("sharing id for auth key #%d: %s",
				i, authKey.String())
		}
		participant, err := NewThresholdParticipant(authKey, prng, protocol, initialRound, slices.Clone(sessionId), transcript.Clone(), sharingId)
		if err != nil {
			return nil, errs.WrapFailed(err, "threshold participant creation")
		}
		participants[i] = participant
	}
	return participants, nil
}
