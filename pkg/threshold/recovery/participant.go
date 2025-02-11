package recovery

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	feldman_vss "github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
)

var (
	_ types.ThresholdParticipant = (*Mislayer)(nil)
)

type Participant struct {
	MySharingId            types.SharingID
	MyIdentityKey          types.AuthKey
	MislayerSharingId      types.SharingID
	MislayerIdentityKey    types.IdentityKey
	RecoverersIdentityKeys ds.Set[types.IdentityKey]
	Protocol               types.ThresholdProtocol
	SharingCfg             types.SharingConfig
	Prng                   io.Reader
	State                  State
}

type State struct {
	feldmanScheme *feldman_vss.Scheme
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}

type Mislayer struct {
	Participant
}

type Recoverer struct {
	Participant

	MySigningKeyShare   *tsignatures.SigningKeyShare
	MyPartialPublicKeys *tsignatures.PartialPublicKeys
	RecovererState      RecovererState
}

type RecovererState struct {
	blindShares        map[types.SharingID]*feldman_vss.Share
	blindVerifications map[types.SharingID][]curves.Point
}

func NewMislayer(myAuthKey types.AuthKey, recoverers ds.Set[types.IdentityKey], protocol types.ThresholdProtocol, prng io.Reader) (*Mislayer, error) {
	if myAuthKey == nil || recoverers == nil || protocol == nil || prng == nil {
		return nil, errs.NewIsNil("arg")
	}
	if recoverers.Contains(myAuthKey) {
		return nil, errs.NewFailed("mislayer is recoverers")
	}
	if !protocol.Participants().Contains(myAuthKey) {
		return nil, errs.NewFailed("mislayer not in protocol participants")
	}
	for recoverer := range recoverers.Iter() {
		if !protocol.Participants().Contains(recoverer) {
			return nil, errs.NewFailed("recoverers not in protocol participants")
		}
	}
	if recoverers.Size() < int(protocol.Threshold()) {
		return nil, errs.NewFailed("recoverers set is too small")
	}

	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, ok := sharingCfg.Reverse().Get(myAuthKey)
	if !ok {
		return nil, errs.NewFailed("auth key not found in protocol participants")
	}

	feldmanScheme, err := feldman_vss.NewScheme(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to initialise feldman-vss scheme")
	}

	p := &Mislayer{
		Participant{
			MySharingId:            mySharingId,
			MyIdentityKey:          myAuthKey,
			MislayerSharingId:      mySharingId,
			MislayerIdentityKey:    myAuthKey,
			RecoverersIdentityKeys: recoverers,
			Protocol:               protocol,
			SharingCfg:             sharingCfg,
			Prng:                   prng,
			State: State{
				feldmanScheme: feldmanScheme,
			},
		},
	}

	return p, nil
}

func NewRecoverer(myAuthKey types.AuthKey, mislayerIdentityKey types.IdentityKey, recoverers ds.Set[types.IdentityKey], protocol types.ThresholdProtocol, mySigningKeyShare *tsignatures.SigningKeyShare, myPartialPublicKeys *tsignatures.PartialPublicKeys, prng io.Reader) (*Recoverer, error) {
	if myAuthKey == nil || recoverers == nil || protocol == nil || prng == nil {
		return nil, errs.NewIsNil("arg")
	}
	if !recoverers.Contains(myAuthKey) {
		return nil, errs.NewFailed("not in recoverers")
	}
	if recoverers.Contains(mislayerIdentityKey) {
		return nil, errs.NewFailed("mislayer in recoverers")
	}
	if !protocol.Participants().Contains(myAuthKey) {
		return nil, errs.NewFailed("recoverer not in protocol participants")
	}
	for recoverer := range recoverers.Iter() {
		if !protocol.Participants().Contains(recoverer) {
			return nil, errs.NewFailed("recoverers not in protocol participants")
		}
	}
	if recoverers.Size() < int(protocol.Threshold()) {
		return nil, errs.NewFailed("recoverers set is too small")
	}

	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, ok := sharingCfg.Reverse().Get(myAuthKey)
	if !ok {
		return nil, errs.NewFailed("auth key not found in protocol participants")
	}
	mislayerSharingId, ok := sharingCfg.Reverse().Get(mislayerIdentityKey)
	if !ok {
		return nil, errs.NewFailed("mislayer key not found in protocol participants")
	}

	feldmanScheme, err := feldman_vss.NewScheme(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to initialise feldman-vss scheme")
	}

	p := &Recoverer{
		Participant: Participant{
			MySharingId:            mySharingId,
			MyIdentityKey:          myAuthKey,
			MislayerSharingId:      mislayerSharingId,
			MislayerIdentityKey:    mislayerIdentityKey,
			RecoverersIdentityKeys: recoverers,
			Protocol:               protocol,
			SharingCfg:             sharingCfg,
			Prng:                   prng,
			State: State{
				feldmanScheme: feldmanScheme,
			},
		},
		MySigningKeyShare:   mySigningKeyShare,
		MyPartialPublicKeys: myPartialPublicKeys,
	}

	return p, nil
}
