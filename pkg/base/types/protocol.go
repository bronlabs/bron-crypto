package types

import (
	"encoding/json"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type ValidationFlag string

type Participant interface {
	IdentityKey() IdentityKey
}

func ValidateParticipant(p Participant) error {
	if err := ValidateIdentityKey(p.IdentityKey()); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	return nil
}

type Protocol interface {
	Curve() curves.Curve // Most supported protocols are algebraic.
	Participants() ds.Set[IdentityKey]
	Flags() ds.Set[ValidationFlag]
	Clone() Protocol
	json.Marshaler
}

func NewProtocol(curve curves.Curve, participants ds.Set[IdentityKey]) (Protocol, error) {
	protocol := &protocol{
		curve:        curve,
		participants: participants,
	}
	if err := ValidateProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "protocol config")
	}
	return protocol, nil
}

func ValidateProtocolConfig(f Protocol) error {
	if f == nil {
		return errs.NewIsNil("protocol config")
	}
	if f.Curve() == nil {
		return errs.NewIsNil("curve")
	}
	if curveSec := curves.ComputationalSecurity(f.Curve()); curveSec < base.ComputationalSecurity {
		return errs.NewCurve("Curve security (%d) below %d bits", curveSec, base.ComputationalSecurity)
	}
	if f.Participants() == nil {
		return errs.NewIsNil("participants return nil")
	}
	if f.Participants().Size() == 0 {
		return errs.NewSize("need to have at least one participant")
	}
	curveName := f.Participants().List()[0].PublicKey().Curve().Name()
	for _, p := range f.Participants().List() {
		if p.PublicKey().Curve().Name() != curveName {
			return errs.NewCurve("participants have different curves")
		}
	}
	return nil
}

func ValidateProtocol(p Participant, f Protocol) error {
	if err := ValidateParticipant(p); err != nil {
		return errs.WrapValidation(err, "participant")
	}
	if err := ValidateProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if !f.Participants().Contains(p.IdentityKey()) {
		return errs.NewMissing("participant is not included in the protocol")
	}
	return nil
}
