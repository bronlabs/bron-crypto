package testutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

var (
	_ fuzzutils.ObjectAdapter[types.AuthKey] = (*AuthKeyAdapter)(nil)
)

type AuthKeyAdapter struct {
	suiteAdapter  fuzzutils.ObjectAdapter[types.SigningSuite]
	scalarAdapter fuzzutils.ObjectAdapter[curves.Scalar]
}

func (a *AuthKeyAdapter) Wrap(underlyer fuzzutils.ObjectUnderlyer) types.AuthKey {
	u1 := underlyer
	u2 := underlyer ^ 0x52d73e8389772284
	suite := a.suiteAdapter.Wrap(u1)
	scalar := a.scalarAdapter.Wrap(u2)
	point := scalar.ScalarField().Curve().Generator().ScalarMul(scalar)

	return &TestAuthKey{
		suite:      suite,
		privateKey: &vanilla.PrivateKey{S: scalar},
		publicKey:  &vanilla.PublicKey{A: point},
	}
}

func (a *AuthKeyAdapter) Unwrap(o types.AuthKey) fuzzutils.ObjectUnderlyer {
	panic("not supported")
}

func (a *AuthKeyAdapter) ZeroValue() types.AuthKey {
	zero := a.scalarAdapter.ZeroValue()

	return &TestAuthKey{
		suite:      a.suiteAdapter.ZeroValue(),
		privateKey: &vanilla.PrivateKey{S: zero},
		publicKey:  &vanilla.PublicKey{A: zero.ScalarField().Curve().Generator().ScalarMul(zero)},
	}
}
