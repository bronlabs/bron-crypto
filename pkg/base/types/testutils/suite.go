package testutils

import (
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ types.SigningSuite = (*BaseSigningSuite)(nil)

type BaseSigningSuite struct {
	curve curves.Curve
	hash  func() hash.Hash
}

func NewSigningSuite(curve curves.Curve, hash func() hash.Hash) types.SigningSuite {
	return &BaseSigningSuite{curve, hash}
}

func (s *BaseSigningSuite) Curve() curves.Curve {
	return s.curve
}

func (s *BaseSigningSuite) Hash() func() hash.Hash {
	return s.hash
}

func (s *BaseSigningSuite) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

/*.--------------------------------------------------------------------------.*/
/*.--------------------------------------------------------------------------.*/

func MakeSigningSuite(curve curves.Curve, h func() hash.Hash) (types.SigningSuite, error) {
	sig := NewSigningSuite(curve, h)
	if err := types.ValidateSigningSuite(sig); err != nil {
		return nil, errs.WrapValidation(err, "sig")
	}
	return sig, nil
}
