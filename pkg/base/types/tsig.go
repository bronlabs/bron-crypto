package types

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type ThresholdSignatureParticipant interface {
	ThresholdParticipant
}

type ThresholdSignatureProtocol interface {
	ThresholdProtocol
	CipherSuite() SignatureProtocol
}

func NewThresholdSignatureProtocol(signatureProtocol SignatureProtocol, participants ds.Set[IdentityKey], threshold uint) (ThresholdSignatureProtocol, error) {
	if err := ValidateSignatureProtocolConfig(signatureProtocol); err != nil {
		return nil, errs.WrapValidation(err, "signature protocol config")
	}
	protocol := &BaseProtocol{
		curve:        signatureProtocol.Curve(),
		hash:         signatureProtocol.Hash(),
		participants: participants,
		threshold:    threshold,
	}
	if err := ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "protocol config")
	}
	return protocol, nil
}

func ValidateThresholdSignatureProtocolConfig(f ThresholdSignatureProtocol) error {
	if f == nil {
		return errs.NewIsNil("protocol config")
	}
	if err := ValidateThresholdProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "threshold protocol config")
	}
	if err := ValidateSignatureProtocolConfig(f.CipherSuite()); err != nil {
		return errs.WrapValidation(err, "signature protocol config")
	}
	return nil
}

func ValidateThresholdSignatureProtocol(p ThresholdSignatureParticipant, f ThresholdSignatureProtocol) error {
	if err := ValidateThresholdProtocol(p, f); err != nil {
		return errs.WrapValidation(err, "threshold protocol")
	}
	if err := validateExtrasSignatureProtocolConfig(f.CipherSuite()); err != nil {
		return errs.WrapValidation(err, "tsig protocol config")
	}
	return nil
}
