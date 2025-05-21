package dkg

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_TRSA_DKG-"
)

var (
	_ types.ThresholdParticipant = (*Participant)(nil)
)

type Participant struct {
	MyAuthKey   types.AuthKey
	MySharingId types.SharingID
	Protocol    types.ThresholdProtocol
	SharingCfg  types.SharingConfig
	Tape        transcripts.Transcript
	Prng        io.Reader
	State       *State
}

type State struct {
	N1        *saferith.Modulus
	N2        *saferith.Modulus
	DShares1  map[types.SharingID]*rep23.IntShare
	DShares2  map[types.SharingID]*rep23.IntShare
	Challenge *saferith.Nat
}

func NewParticipant(sid []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, tape transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if len(sid) == 0 || authKey == nil || protocol == nil || tape == nil || prng == nil {
		return nil, errs.NewIsNil("argument")
	}

	tape.AppendMessages(transcriptLabel, sid)
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, ok := sharingCfg.Reverse().Get(authKey)
	if !ok {
		return nil, errs.NewFailed("auth key not found in protocol participants")
	}

	p := &Participant{
		MyAuthKey:   authKey,
		MySharingId: mySharingId,
		SharingCfg:  sharingCfg,
		Protocol:    protocol,
		Tape:        tape,
		Prng:        prng,
		State:       &State{},
	}
	if types.ValidateThresholdProtocol(p, protocol) != nil {
		return nil, errs.NewValidation("invalid protocol")
	}

	return p, nil
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}
