package testutils

import (
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ types.Protocol = (*BaseProtocol)(nil)

type BaseProtocol struct {
	curve        curves.Curve
	participants ds.Set[types.IdentityKey]
}

func NewProtocol[KeyT types.IdentityKey](curve curves.Curve, participants ...KeyT) (types.Protocol, error) {
	participantList := make([]types.IdentityKey, len(participants))
	for i, p := range participants {
		participantList[i] = p
	}
	participantSet := hashset.NewHashableHashSet(participantList...)
	protocol := &BaseProtocol{
		curve:        curve,
		participants: participantSet,
	}
	if err := types.ValidateProtocol(protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid protocol")
	}
	return protocol, nil
}

func (p *BaseProtocol) Curve() curves.Curve {
	return p.curve
}

func (p *BaseProtocol) Participants() ds.Set[types.IdentityKey] {
	return p.participants
}

func (*BaseProtocol) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

/*.--------------------------------------------------------------------------.*/

var _ types.ThresholdProtocol = (*BaseThresholdProtocol)(nil)

type BaseThresholdProtocol struct {
	BaseProtocol
	threshold     uint
	sharingConfig types.SharingConfig
}

func NewThresholdProtocol(curve curves.Curve, sharingConfig types.SharingConfig, threshold uint, participants ...types.IdentityKey) (types.ThresholdProtocol, error) {
	participantList := make([]types.IdentityKey, len(participants))
	for i, p := range participants {
		participantList[i] = p
	}
	participantSet := hashset.NewHashableHashSet(participantList...)
	protocol := &BaseThresholdProtocol{
		BaseProtocol: BaseProtocol{
			curve:        curve,
			participants: participantSet,
		},
		threshold:     threshold,
		sharingConfig: sharingConfig,
	}
	if err := types.ValidateThresholdProtocol(protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid threshold protocol")
	}
	return protocol, nil

}

func (p *BaseThresholdProtocol) Threshold() uint {
	return p.threshold
}

func (p *BaseThresholdProtocol) TotalParties() uint {
	return uint(p.participants.Size())
}

func (p *BaseThresholdProtocol) SharingConfig() types.SharingConfig {
	return p.sharingConfig
}

/*.--------------------------------------------------------------------------.*/

type BaseThresholdSignatureProtocol struct {
	BaseThresholdProtocol
	signingSuite types.SigningSuite
}

func NewThresholdSignatureProtocol(curve curves.Curve, sharingConfig types.SharingConfig, signingSuite types.SigningSuite, threshold uint, participants ...types.IdentityKey) (types.ThresholdSignatureProtocol, error) {
	participantList := make([]types.IdentityKey, len(participants))
	for i, p := range participants {
		participantList[i] = p
	}
	participantSet := hashset.NewHashableHashSet(participantList...)
	protocol := &BaseThresholdSignatureProtocol{
		BaseThresholdProtocol: BaseThresholdProtocol{
			BaseProtocol: BaseProtocol{
				curve:        curve,
				participants: participantSet,
			},
			threshold:     threshold,
			sharingConfig: sharingConfig,
		},
		signingSuite: signingSuite,
	}
	if err := types.ValidateThresholdSignatureProtocol(protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid threshold protocol")
	}
	return protocol, nil
}

func (p *BaseThresholdSignatureProtocol) Hash() func() hash.Hash {
	return p.signingSuite.Hash()
}

func (p *BaseThresholdSignatureProtocol) SigningSuite() types.SigningSuite {
	return p.signingSuite
}
