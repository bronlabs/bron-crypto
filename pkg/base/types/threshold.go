package types

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type SharingID uint
type SharingConfig AbstractIdentitySpace[SharingID]

type ThresholdParticipant interface {
	MPCParticipant
	SharingId() SharingID
}

func validateThresholdParticipant(p ThresholdParticipant) error {
	if id := p.SharingId(); id <= 0 {
		return errs.NewIdentifier("sharing id must be a positive number")
	}
	return nil
}

type ThresholdProtocol interface {
	MPCProtocol
	Threshold() uint
	TotalParties() uint
}

func NewThresholdProtocol(curve curves.Curve, participants ds.HashSet[IdentityKey], threshold uint) (ThresholdProtocol, error) {
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
	if err := ValidateMPCProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "input for protocol is not an mpc protocol")
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
	if err := ValidateMPCProtocol(p, f); err != nil {
		return errs.WrapValidation(err, "mpc protocol")
	}
	if err := validateThresholdParticipant(p); err != nil {
		return errs.WrapValidation(err, "threshold protocol")
	}
	if err := validateExtrasThresholdProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "threshold protocol config")
	}
	mySharingId, exists := DeriveSharingConfig(f.Participants()).LookUpRight(p.IdentityKey())
	if !exists {
		return errs.NewMissing("my sharing id couldn't be computed from the protocol config")
	}
	if mySharingId != p.SharingId() {
		return errs.NewIdentifier("sharing id (%d) != what it should be (%d)", p.SharingId(), mySharingId)
	}
	return nil
}

func DeriveSharingConfig(identityKeys ds.HashSet[IdentityKey]) SharingConfig {
	return NewAbstractIdentitySpace[SharingID](identityKeys)
}
