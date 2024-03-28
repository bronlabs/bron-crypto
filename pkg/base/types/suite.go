package types

import (
	"encoding/json"
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type SigningSuite interface {
	Curve() curves.Curve
	Hash() func() hash.Hash
	json.Marshaler
}

func ValidateSigningSuite(ss SigningSuite) error {
	if ss == nil {
		return errs.NewIsNil("signing suite is nil")
	}
	if ss.Curve() == nil {
		return errs.NewIsNil("curve")
	}
	if ss.Hash() == nil {
		return errs.NewIsNil("hash function")
	}
	return nil
}
