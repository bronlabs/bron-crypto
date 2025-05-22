package refresh

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_TRSA_REFRESH-"
)

var (
	_ types.ThresholdParticipant = (*Participant)(nil)
)

type Participant struct {
	MyAuthKey   types.AuthKey
	MySharingId types.SharingID
	MyShard     *trsa.Shard
	Protocol    types.ThresholdProtocol
	SharingCfg  types.SharingConfig
	Tape        transcripts.Transcript
	Prng        io.Reader
	State       *State
}

type State struct {
	D1Share   *rep23.IntShare
	D2Share   *rep23.IntShare
	Challenge *saferith.Nat
}

func NewParticipant(sid []byte, authKey types.AuthKey, shard *trsa.Shard, protocol types.ThresholdProtocol, tape transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if len(sid) == 0 || authKey == nil || shard == nil || protocol == nil || tape == nil || prng == nil {
		return nil, errs.NewIsNil("argument")
	}

	tape.AppendMessages(transcriptLabel, sid)
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	sharingId, ok := sharingCfg.Reverse().Get(authKey)
	if !ok {
		return nil, errs.NewFailed("sharing config not found")
	}

	p := &Participant{
		MyAuthKey:   authKey,
		MySharingId: sharingId,
		MyShard:     shard,
		Protocol:    protocol,
		SharingCfg:  sharingCfg,
		Tape:        tape,
		Prng:        prng,
		State:       &State{},
	}
	if err := types.ValidateThresholdProtocol(p, protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid threshold protocol")
	}

	return p, nil
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}
