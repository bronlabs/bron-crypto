package types

import "github.com/copperexchange/krypton-primitives/pkg/base/errs"

func ValidateConfig(f any) error {
	// Must be from least general to most
	switch t := f.(type) {
	case ThresholdSignatureProtocol:
		return ValidateThresholdSignatureProtocolConfig(t)
	case ThresholdProtocol:
		return ValidateThresholdProtocolConfig(t)
	case Protocol:
		return ValidateProtocolConfig(t)
	case SigningSuite:
		return ValidateSigningSuite(t)
	default:
		return errs.NewType("protocol is not recognised %v", t)
	}
}

func ValidateProtocolParticipant(p any) error {
	// Must be from least general to most
	switch t := p.(type) {
	case ThresholdSignatureParticipant, ThresholdParticipant: //nolint:gocritic // false positive
		return validateThresholdParticipant(t.(ThresholdParticipant)) //nolint:forcetypeassert // trivial
	case Participant:
		return ValidateParticipant(t)
	default:
		return errs.NewType("protocol is not recognised %v", t)
	}
}

func ValidateAnyProtocol(participant, protocol any) error {
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
	case Protocol:
		p, ok := participant.(Participant)
		if !ok {
			return errs.NewType("participant type != protocol type")
		}
		return ValidateProtocol(p, f)
	case SigningSuite:
		if participant != nil {
			return errs.NewType("participant type of the single party signature protocol is not nil")
		}
		return ValidateSigningSuite(f)
	default:
		return errs.NewType("protocol is not recognised %v", f)
	}
}
