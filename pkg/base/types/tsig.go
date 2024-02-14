package types

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type ThresholdSignatureParticipant interface {
	ThresholdParticipant
	IsSignatureAggregator() bool
}

type ThresholdSignatureProtocol interface {
	ThresholdProtocol
	CipherSuite() SignatureProtocol
	SignatureAggregators() ds.HashSet[IdentityKey]
}

func NewThresholdSignatureProtocol(signatureProtocol SignatureProtocol, participants ds.HashSet[IdentityKey], threshold uint, signatureAggregators ds.HashSet[IdentityKey]) (ThresholdSignatureProtocol, error) {
	if err := ValidateSignatureProtocolConfig(signatureProtocol); err != nil {
		return nil, errs.WrapValidation(err, "signature protocol config")
	}
	protocol := &protocol{
		curve:                signatureProtocol.Curve(),
		hash:                 signatureProtocol.Hash(),
		participants:         participants,
		threshold:            threshold,
		signatureAggregators: signatureAggregators,
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
	if err := validateExtrasThresholdSignatureProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "tsig")
	}
	return nil
}

func validateExtrasThresholdSignatureProtocolConfig(f ThresholdSignatureProtocol) error {
	sa := f.SignatureAggregators()
	if sa == nil {
		return errs.NewIsNil("Signature aggregators")
	}
	if sa.Size() == 0 {
		return errs.NewSize("need to have at least one signature aggregator")
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
	if err := validateExtrasThresholdSignatureProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "tsig protocol config")
	}
	if p.IsSignatureAggregator() && !f.SignatureAggregators().Contains(p.IdentityKey()) {
		return errs.NewType("participant should not be an aggregator according to protocol config")
	}
	return nil
}
