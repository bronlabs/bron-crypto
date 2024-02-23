package types

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type MPCParticipant interface {
	GenericParticipant
	WithIdentityKey
}

func validateMPCParticipant(p MPCParticipant) error {
	if err := ValidateIdentityKey(p.IdentityKey()); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	return nil
}

type MPCProtocol interface {
	GenericProtocol
	Participants() ds.Set[IdentityKey]
}

func NewMPCProtocol(curve curves.Curve, participants ds.Set[IdentityKey]) (MPCProtocol, error) {
	protocol := &protocol{
		curve:        curve,
		participants: participants,
	}
	if err := ValidateMPCProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "protocol config")
	}
	return protocol, nil
}

func ValidateMPCProtocolConfig(f MPCProtocol) error {
	if f == nil {
		return errs.NewIsNil("protocol config")
	}
	if err := ValidateGenericProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "generic protocol config")
	}
	if err := validateExtrasMPCProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "mpc protocol config")
	}
	return nil
}

func validateExtrasMPCProtocolConfig(f MPCProtocol) error {
	if f.Participants() == nil {
		return errs.NewIsNil("participants return nil")
	}
	if f.Participants().Size() == 0 {
		return errs.NewSize("need to have at least one participant")
	}
	return nil
}

func ValidateMPCProtocol(p MPCParticipant, f MPCProtocol) error {
	if err := ValidateGenericProtocol(p, f); err != nil {
		return errs.WrapValidation(err, "generic protocol")
	}
	if err := validateMPCParticipant(p); err != nil {
		return errs.WrapValidation(err, "mpc participant")
	}
	if err := validateExtrasMPCProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "mpc protocol config")
	}
	if !f.Participants().Contains(p.IdentityKey()) {
		return errs.NewMissing("participant is not included in the protocol")
	}
	return nil
}

type RoundMessages[Message any] ds.Map[IdentityKey, Message]

func NewRoundMessages[Message any]() RoundMessages[Message] {
	return hashmap.NewHashableHashMap[IdentityKey, Message]()
}
