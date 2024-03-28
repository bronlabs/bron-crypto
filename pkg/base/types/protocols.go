package types

import (
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Protocol interface {
	// Curve returns the curve used by the protocol. Most supported protocols are algebraic.
	Curve() curves.Curve
	// Participants returns the set of participants in the protocol.
	Participants() ds.Set[IdentityKey]
	// MarshalJSON serializes the protocol in JSON encoding.
	json.Marshaler
}

func ValidateProtocol(f Protocol) error {
	if f == nil {
		return errs.NewIsNil("protocol config")
	}
	if f.Curve() == nil {
		return errs.NewIsNil("curve")
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

/*.--------------------------------------------------------------------------.*/

// ThresholdProtocol is a protocol that requires a threshold of participants to complete.
type ThresholdProtocol interface {
	Protocol
	// Threshold returns the number of participants required to reconstruct the secret.
	Threshold() uint
	// TotalParties returns the total number of participants in the protocol.
	TotalParties() uint
	// SharingConfig returns the sharing configuration of all participants in the protocol.
	SharingConfig() SharingConfig
}

func ValidateThresholdProtocol(f ThresholdProtocol) error {
	if f == nil {
		return errs.NewIsNil("threshold protocol config")
	}
	if err := ValidateProtocol(f); err != nil {
		return errs.WrapValidation(err, "input for protocol is not an mpc protocol")
	}
	if err := validateExtrasThresholdProtocol(f); err != nil {
		return errs.WrapValidation(err, "threshold protocol")
	}
	return nil
}

func validateExtrasThresholdProtocol(f ThresholdProtocol) error {
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

/*.--------------------------------------------------------------------------.*/

type ThresholdSignatureProtocol interface {
	ThresholdProtocol
	SigningSuite() SigningSuite
}

func ValidateThresholdSignatureProtocol(f ThresholdSignatureProtocol) error {
	if f == nil {
		return errs.NewIsNil("protocol config")
	}
	if err := ValidateThresholdProtocol(f); err != nil {
		return errs.WrapValidation(err, "threshold protocol config")
	}
	if err := ValidateSigningSuite(f.SigningSuite()); err != nil {
		return errs.WrapValidation(err, "signature protocol config")
	}
	return nil
}
