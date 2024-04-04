package types

import (
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type SigningSuite interface {
	Curve() curves.Curve
	Hash() func() hash.Hash
}

func NewSigningSuite(curve curves.Curve, hashFunc func() hash.Hash) (SigningSuite, error) {
	protocol := &protocol{
		curve: curve,
		hash:  hashFunc,
	}
	if err := ValidateSigningSuite(protocol); err != nil {
		return nil, errs.WrapValidation(err, "signing suite")
	}
	return protocol, nil
}

func ValidateSigningSuite(f SigningSuite) error {
	if c := f.Curve(); c == nil {
		return errs.NewIsNil("curve")
	}
	if h := f.Hash(); h == nil {
		return errs.NewIsNil("hash function")
	}
	return nil
}
