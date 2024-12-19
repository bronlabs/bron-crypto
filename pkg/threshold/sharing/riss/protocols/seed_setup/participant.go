package riss_seed_setup

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var (
	_ types.ThresholdParticipant = (*Participant)(nil)
)

type Participant struct {
	MyIdentityKey      types.IdentityKey
	MySharingId        types.SharingID
	Protocol           types.ThresholdProtocol
	SharingCfg         types.SharingConfig
	Tape               transcripts.Transcript
	Prng               io.Reader
	MaxUnqualifiedSets []riss.SharingIdSet
	State              *State
}

type State struct {
	Seeds map[riss.SharingIdSet][64]byte
}

func NewParticipant(myIdentityKey types.IdentityKey, protocol types.ThresholdProtocol, tape transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if myIdentityKey == nil || protocol == nil || tape == nil || prng == nil {
		return nil, errs.NewIsNil("argument is nil")
	}
	if !protocol.Participants().Contains(myIdentityKey) {
		return nil, errs.NewFailed("invalid protocol")
	}
	if protocol.Threshold() < 2 || protocol.TotalParties() < 2 || (protocol.Threshold()-1)*2 >= protocol.TotalParties() {
		return nil, errs.NewFailed("invalid access structure")
	}

	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, ok := sharingCfg.Reverse().Get(myIdentityKey)
	if !ok {
		return nil, errs.NewFailed("invalid identity key")
	}

	maxUnqualifiedSets, err := riss.BuildSortedMaxUnqualifiedSets(protocol.Threshold(), protocol.TotalParties())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to build max unqualified sets")
	}

	p := &Participant{
		MyIdentityKey:      myIdentityKey,
		MySharingId:        mySharingId,
		Protocol:           protocol,
		SharingCfg:         sharingCfg,
		Tape:               tape,
		Prng:               prng,
		MaxUnqualifiedSets: maxUnqualifiedSets,
		State:              &State{},
	}

	return p, nil
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}
