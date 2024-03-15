package types

import (
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type SignatureProtocol interface {
	GenericProtocol
	Curve() curves.Curve
	Hash() func() hash.Hash
}

func NewSignatureProtocol(curve curves.Curve, hashFunc func() hash.Hash) (SignatureProtocol, error) {
	protocol := &BaseProtocol{
		curve: curve,
		hash:  hashFunc,
	}
	if err := ValidateSignatureProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "protocol config")
	}
	return protocol, nil
}

func ValidateSignatureProtocolConfig(f SignatureProtocol) error {
	if err := ValidateGenericProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "input for protocol is not a generic protocol")
	}
	if err := validateExtrasSignatureProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "signature protocol")
	}
	return nil
}

func validateExtrasSignatureProtocolConfig(f SignatureProtocol) error {
	if c := f.Curve(); c == nil {
		return errs.NewIsNil("curve")
	}
	if h := f.Hash(); h == nil {
		return errs.NewIsNil("hash function")
	}
	return nil
}
