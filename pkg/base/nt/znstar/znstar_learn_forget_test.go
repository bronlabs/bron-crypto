package znstar_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

func TestForgetOrder(t *testing.T) {
	t.Parallel()

	// Create RSA group with known order
	p, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(13)
	require.NoError(t, err)

	rsaGroup, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Create a unit in the group with known order
	zmod := rsaGroup.AmbientGroup()
	u, err := zmod.FromUint64(2)
	require.NoError(t, err)
	unit, err := rsaGroup.FromUint(u)
	require.NoError(t, err)
	require.NotNil(t, unit)

	// Check it's in known order group
	require.False(t, unit.IsUnknownOrder())

	// Forget the order
	unitUnknown := unit.ForgetOrder()
	require.NotNil(t, unitUnknown)

	// Check it's now in unknown order group
	require.True(t, unitUnknown.IsUnknownOrder())

	// Values should be the same
	require.True(t, unit.Value().Equal(unitUnknown.Value()) == 0x01) // ct.True

	// Modulus should be the same
	require.True(t, unit.Modulus().Equal(unitUnknown.Modulus()))
}

func TestLearnOrder(t *testing.T) {
	t.Parallel()

	// Create n = p*q
	p, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(13)
	require.NoError(t, err)
	n := p.Mul(q)

	// Create unit in unknown order group
	unknownGroup, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	zmod := unknownGroup.AmbientGroup()
	u, err := zmod.FromUint64(2)
	require.NoError(t, err)
	unitUnknown, err := unknownGroup.FromUint(u)
	require.NoError(t, err)
	require.True(t, unitUnknown.IsUnknownOrder())

	// Create known order group with same modulus
	knownGroup, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Learn the order
	unitKnown := unitUnknown.LearnOrder(knownGroup)
	require.NotNil(t, unitKnown)

	// Check it's now in known order group
	require.False(t, unitKnown.IsUnknownOrder())

	// Values should be the same
	require.True(t, unitUnknown.Value().Equal(unitKnown.Value()) == 0x01) // ct.True

	// Modulus should be the same
	require.True(t, unitUnknown.Modulus().Equal(unitKnown.Modulus()))
}

func TestForgetOrder_Paillier(t *testing.T) {
	t.Parallel()

	// Create Paillier group with known order
	p, err := num.NPlus().FromUint64(7)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)

	paillierGroup, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Create a unit
	zmod := paillierGroup.AmbientGroup()
	u, err := zmod.FromUint64(2)
	require.NoError(t, err)
	unit, err := paillierGroup.FromUint(u)
	require.NoError(t, err)

	// Check it's in known order group
	require.False(t, unit.IsUnknownOrder())

	// Forget the order
	unitUnknown := unit.ForgetOrder()

	// Check it's now in unknown order group
	require.True(t, unitUnknown.IsUnknownOrder())

	// Values should be the same
	require.True(t, unit.Value().Equal(unitUnknown.Value()) == 0x01) // ct.True
}

func TestMixedOrderOperations_ShouldFail(t *testing.T) {
	t.Parallel()

	// Create two groups with different order knowledge but same modulus
	p, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(13)
	require.NoError(t, err)
	n := p.Mul(q)

	// Known order group
	knownGroup, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Unknown order group
	unknownGroup, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	// Create units in each group
	zmodKnown := knownGroup.AmbientGroup()
	uKnown, err := zmodKnown.FromUint64(2)
	require.NoError(t, err)
	unitKnown, err := knownGroup.FromUint(uKnown)
	require.NoError(t, err)

	zmodUnknown := unknownGroup.AmbientGroup()
	uUnknown, err := zmodUnknown.FromUint64(3)
	require.NoError(t, err)
	unitUnknown, err := unknownGroup.FromUint(uUnknown)
	require.NoError(t, err)

	// Operations between mixed order units should panic
	require.Panics(t, func() {
		_ = unitKnown.Op(unitUnknown)
	}, "Operating on units with mixed order knowledge should panic")

	require.Panics(t, func() {
		_ = unitKnown.Mul(unitUnknown)
	}, "Multiplying units with mixed order knowledge should panic")

	require.Panics(t, func() {
		_ = unitKnown.Div(unitUnknown)
	}, "Dividing units with mixed order knowledge should panic")
}

func TestRoundTrip_ForgetAndLearn(t *testing.T) {
	t.Parallel()

	// Create RSA group with known order
	p, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(13)
	require.NoError(t, err)

	rsaGroup, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Create a unit
	zmod := rsaGroup.AmbientGroup()
	u, err := zmod.FromUint64(5)
	require.NoError(t, err)
	original, err := rsaGroup.FromUint(u)
	require.NoError(t, err)
	require.False(t, original.IsUnknownOrder())

	// Forget then learn back
	forgotten := original.ForgetOrder()
	require.True(t, forgotten.IsUnknownOrder())

	learned := forgotten.LearnOrder(rsaGroup)
	require.False(t, learned.IsUnknownOrder())

	// All should have the same value
	require.True(t, original.Value().Equal(forgotten.Value()) == 0x01) // ct.True
	require.True(t, original.Value().Equal(learned.Value()) == 0x01)   // ct.True
	require.True(t, forgotten.Value().Equal(learned.Value()) == 0x01)  // ct.True

	// Operations should work on compatible units
	result := original.Op(learned)
	require.NotNil(t, result)
	// 5 * 5 = 25 ≡ 12 (mod 143)
	require.Equal(t, uint64(25), result.Value().Big().Uint64())

	// But not between different order knowledge
	require.Panics(t, func() {
		_ = original.Op(forgotten)
	}, "Cannot operate on units with different order knowledge")
}
