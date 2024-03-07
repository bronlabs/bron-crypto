package types

import (
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type GenericProtocol interface {
	Curve() curves.Curve // At this point all supported protocols are algebraic.
	json.Marshaler
}

func NewGenericProtocol(curve curves.Curve) (GenericProtocol, error) {
	protocol := &protocol{
		curve: curve,
	}
	if err := ValidateGenericProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "protocol config")
	}
	return protocol, nil
}

func ValidateGenericProtocolConfig(f GenericProtocol) error {
	if f == nil {
		return errs.NewIsNil("input is nil")
	}
	if f.Curve() == nil {
		return errs.NewIsNil("curve")
	}
	return nil
}

func ValidateGenericProtocol(f GenericProtocol) error {
	if err := ValidateGenericProtocolConfig(f); err != nil {
		return errs.WrapValidation(err, "input for protocol is not a generic protocol")
	}
	return nil
}
