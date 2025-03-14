package types

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type ThresholdSignatureParticipant interface {
	ThresholdParticipant
	Quorum() ds.Set[IdentityKey]
}

type ThresholdSignatureProtocol interface {
	ThresholdProtocol
	SigningSuite() SigningSuite
}

func NewThresholdSignatureProtocol(signingSuite SigningSuite, participants ds.Set[IdentityKey], threshold uint) (ThresholdSignatureProtocol, error) {
	if err := ValidateSigningSuite(signingSuite); err != nil {
		return nil, errs.WrapValidation(err, "signature protocol config")
	}
	protocol := &protocol{
		curve:        signingSuite.Curve(),
		hash:         signingSuite.Hash(),
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
	if err := ValidateSigningSuite(f.SigningSuite()); err != nil {
		return errs.WrapValidation(err, "signature protocol config")
	}
	return nil
}

func ValidateThresholdSignatureProtocol(p ThresholdSignatureParticipant, f ThresholdSignatureProtocol) error {
	if err := ValidateThresholdProtocol(p, f); err != nil {
		return errs.WrapValidation(err, "threshold protocol")
	}
	if err := ValidateSigningSuite(f.SigningSuite()); err != nil {
		return errs.WrapValidation(err, "tsig protocol config")
	}
	return nil
}
