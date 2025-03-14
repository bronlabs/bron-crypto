package types

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type SharingID uint

func (id SharingID) ToScalar(scalarField curves.ScalarField) curves.Scalar {
	return scalarField.New(uint64(id))
}

type SharingConfig AbstractIdentitySpace[SharingID]

type ThresholdParticipant interface {
	Participant
	SharingId() SharingID
}

func validateThresholdParticipant(p ThresholdParticipant) error {
	if id := p.SharingId(); id <= 0 {
		return errs.NewValue("sharing id must be a positive number")
	}
	return nil
}

type ThresholdProtocol interface {
	Protocol
	Threshold() uint
	TotalParties() uint
}

func NewThresholdProtocol(curve curves.Curve, participants ds.Set[IdentityKey], threshold uint) (ThresholdProtocol, error) {
	protocol := &protocol{
		curve:        curve,
		participants: participants,
		threshold:    threshold,
	}
	if err := ValidateThresholdProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "protocol config")
	}
	return protocol, nil
}

func ValidateThresholdProtocolConfig(f ThresholdProtocol) error {
	if f == nil {
		return errs.NewIsNil("protocol config")
	}
	if err := ValidateProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "input for protocol is not a protocol")
	}
	if err := validateExtrasThresholdProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "threshold protocol")
	}
	return nil
}

func validateExtrasThresholdProtocolConfig(f ThresholdProtocol) error {
	t := f.Threshold()
	if t < 2 {
		return errs.NewValue("t < 2")
	}
	n := f.TotalParties()
	if n < t {
		return errs.NewValue(" n < t")
	}
	if int(n) != f.Participants().Size() {
		return errs.NewSize("n != size of participants")
	}
	return nil
}

func ValidateThresholdProtocol(p ThresholdParticipant, f ThresholdProtocol) error {
	if err := ValidateProtocol(p, f); err != nil {
		return errs.WrapValidation(err, "protocol")
	}
	if err := validateThresholdParticipant(p); err != nil {
		return errs.WrapValidation(err, "threshold protocol")
	}
	if err := validateExtrasThresholdProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "threshold protocol config")
	}
	// TODO: fix protocol validation when quorum is not total participants.
	// mySharingId, exists := DeriveSharingConfig(f.Participants()).Reverse().Get(p.IdentityKey())
	// if !exists {
	// 	return errs.NewMissing("my sharing id couldn't be computed from the protocol config")
	// }
	// if mySharingId != p.SharingId() {
	// 	return errs.NewValue("sharing id (%d) != what it should be (%d)", p.SharingId(), mySharingId)
	// }
	return nil
}

func DeriveSharingConfig(identityKeys ds.Set[IdentityKey]) SharingConfig {
	return NewAbstractIdentitySpace[SharingID](identityKeys)
}
