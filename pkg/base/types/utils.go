package types

import "github.com/copperexchange/krypton-primitives/pkg/base/errs"

func ValidateProtocolConfig(f any) error {
	// Must be from least general to most
	switch t := f.(type) {
	case ThresholdSignatureProtocol:
		return ValidateThresholdSignatureProtocolConfig(t)
	case ThresholdProtocol:
		return ValidateThresholdProtocolConfig(t)
	case MPCProtocol:
		return ValidateMPCProtocolConfig(t)
	case SignatureProtocol:
		return ValidateSignatureProtocolConfig(t)
	case GenericProtocol:
		return ValidateGenericProtocolConfig(t)
	default:
		return errs.NewType("protocol is not recognised %v", t)
	}
}

func ValidateProtocolParticipant(p any) error {
	// Must be from least general to most
	switch t := p.(type) {
	case ThresholdSignatureParticipant, ThresholdParticipant: //nolint:gocritic // false positive
		return validateThresholdParticipant(t.(ThresholdParticipant)) //nolint:forcetypeassert // trivial
	case MPCParticipant:
		return validateMPCParticipant(t)
	default:
		return errs.NewType("protocol is not recognised %v", t)
	}
}

func ValidateProtocol(participant, protocol any) error {
	// Must be from least general to most
	switch f := protocol.(type) {
	case ThresholdSignatureProtocol:
		p, ok := participant.(ThresholdSignatureParticipant)
		if !ok {
			return errs.NewType("participant type != protocol type")
		}
		return ValidateThresholdSignatureProtocol(p, f)
	case ThresholdProtocol:
		p, ok := participant.(ThresholdParticipant)
		if !ok {
			return errs.NewType("participant type != protocol type")
		}
		return ValidateThresholdProtocol(p, f)
	case MPCProtocol:
		p, ok := participant.(MPCParticipant)
		if !ok {
			return errs.NewType("participant type != protocol type")
		}
		return ValidateMPCProtocol(p, f)
	case SignatureProtocol:
		if participant != nil {
			return errs.NewType("participant type of the single party signature protocol is not nil")
		}
		return ValidateSignatureProtocolConfig(f)
	case GenericProtocol:
		return ValidateGenericProtocol(f)
	default:
		return errs.NewType("protocol is not recognised %v", f)
	}
}
