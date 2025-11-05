package znstar_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// Test Unit serialisation with unknown order
func TestUnit_CBOR_UnknownOrder(t *testing.T) {
	t.Parallel()

	// Create RSA group with unknown order
	n, err := num.NPlus().FromUint64(143) // 11 * 13
	require.NoError(t, err)

	group, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	// Create a unit
	zmod := group.AmbientGroup()
	u, err := zmod.FromUint64(5)
	require.NoError(t, err)
	unit, err := group.FromUint(u)
	require.NoError(t, err)
	require.True(t, unit.IsUnknownOrder())

	// Marshal to CBOR
	data, err := serde.MarshalCBOR(unit)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	decoded, err := serde.UnmarshalCBOR[znstar.Unit](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify properties
	require.True(t, decoded.IsUnknownOrder())
	require.True(t, unit.Value().Equal(decoded.Value()) == ct.True)
	require.True(t, unit.Modulus().Equal(decoded.Modulus()))

	// Test operations work on decoded unit
	unit2, err := group.FromUint(u)
	require.NoError(t, err)
	result1 := unit.Mul(unit2)
	result2 := decoded.Mul(unit2)
	require.True(t, result1.Value().Equal(result2.Value()) == ct.True)
}

// Test Unit serialisation with known order (RSA)
func TestUnit_CBOR_KnownOrder_RSA(t *testing.T) {
	t.Parallel()

	// Create RSA group with known order
	p, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(13)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Create a unit
	zmod := group.AmbientGroup()
	u, err := zmod.FromUint64(5)
	require.NoError(t, err)
	unit, err := group.FromUint(u)
	require.NoError(t, err)
	require.False(t, unit.IsUnknownOrder())

	// Marshal to CBOR
	data, err := serde.MarshalCBOR(unit)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	decoded, err := serde.UnmarshalCBOR[znstar.Unit](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify properties
	require.False(t, decoded.IsUnknownOrder())
	require.True(t, unit.Value().Equal(decoded.Value()) == ct.True)
	require.True(t, unit.Modulus().Equal(decoded.Modulus()))

	// Verify order is preserved
	require.False(t, unit.Group().Order().IsUnknown())
	require.False(t, decoded.Group().Order().IsUnknown())
	require.True(t, unit.Group().Order().Equal(decoded.Group().Order()))

	// Test operations work
	unit2, err := group.FromUint(u)
	require.NoError(t, err)
	result1 := unit.Mul(unit2)
	result2 := decoded.Mul(unit2)
	require.True(t, result1.Value().Equal(result2.Value()) == ct.True)
}

// Test Unit serialisation with known order (Paillier)
func TestUnit_CBOR_KnownOrder_Paillier(t *testing.T) {
	t.Parallel()

	// Create Paillier group with known order
	p, err := num.NPlus().FromUint64(7)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Create a unit
	zmod := group.AmbientGroup()
	u, err := zmod.FromUint64(100)
	require.NoError(t, err)
	unit, err := group.FromUint(u)
	require.NoError(t, err)
	require.False(t, unit.IsUnknownOrder())

	// Marshal to CBOR
	data, err := serde.MarshalCBOR(unit)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	decoded, err := serde.UnmarshalCBOR[znstar.Unit](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify properties
	require.False(t, decoded.IsUnknownOrder())
	require.True(t, unit.Value().Equal(decoded.Value()) == ct.True)
	require.True(t, unit.Modulus().Equal(decoded.Modulus()))

	// Test operations work
	unit2, err := group.FromUint(u)
	require.NoError(t, err)
	result1 := unit.Mul(unit2)
	result2 := decoded.Mul(unit2)
	require.True(t, result1.Value().Equal(result2.Value()) == ct.True)
}

// Test UnitGroup interface serialisation - RSA unknown order
func TestUnitGroup_InterfaceSerialization_RSAUnknown(t *testing.T) {
	t.Parallel()

	// Create RSA group with unknown order
	n, err := num.NPlus().FromUint64(143)
	require.NoError(t, err)

	original, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	// Serialise through UnitGroup interface
	var group znstar.UnitGroup = original

	data, err := serde.MarshalCBOR(group)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize back to UnitGroup interface
	decoded, err := serde.UnmarshalCBOR[znstar.UnitGroup](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify modulus matches
	require.True(t, original.Modulus().Equal(decoded.Modulus()))
	require.True(t, original.Order().IsUnknown())
	require.True(t, decoded.Order().IsUnknown())

	// Test creating units in both groups
	zmod1 := original.AmbientGroup()
	u1, err := zmod1.FromUint64(5)
	require.NoError(t, err)
	unit1, err := original.FromUint(u1)
	require.NoError(t, err)

	zmod2 := decoded.AmbientGroup()
	u2, err := zmod2.FromUint64(5)
	require.NoError(t, err)
	unit2, err := decoded.FromUint(u2)
	require.NoError(t, err)

	require.True(t, unit1.Value().Equal(unit2.Value()) == ct.True)
}

// Test RSAGroup interface serialisation - known order
func TestRSAGroupKnownOrder_InterfaceSerialization(t *testing.T) {
	t.Parallel()

	// Create RSA group with known order
	p, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(13)
	require.NoError(t, err)

	original, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Serialise through RSAGroupKnownOrder interface
	var group = original

	data, err := serde.MarshalCBOR(group)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize back to RSAGroupKnownOrder interface
	decoded, err := serde.UnmarshalCBOR[znstar.RSAGroupKnownOrder](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify modulus and order match
	require.True(t, original.Modulus().Equal(decoded.Modulus()))
	require.False(t, original.Order().IsUnknown())
	require.False(t, decoded.Order().IsUnknown())
	require.True(t, original.Order().Equal(decoded.Order()))

	// Test arithmetic is preserved
	require.NotNil(t, original.Arithmetic())
	require.NotNil(t, decoded.Arithmetic())

	// Create units and verify operations work
	zmod1 := original.AmbientGroup()
	u1, err := zmod1.FromUint64(5)
	require.NoError(t, err)
	unit1, err := original.FromUint(u1)
	require.NoError(t, err)

	zmod2 := decoded.AmbientGroup()
	u2, err := zmod2.FromUint64(5)
	require.NoError(t, err)
	unit2, err := decoded.FromUint(u2)
	require.NoError(t, err)

	// Test exponentiation
	exp := num.N().FromUint64(3)
	result1 := unit1.Exp(exp)
	result2 := unit2.Exp(exp)
	require.True(t, result1.Value().Equal(result2.Value()) == ct.True)
}

// Test PaillierGroupKnownOrder interface serialisation
func TestPaillierGroupKnownOrder_InterfaceSerialization(t *testing.T) {
	t.Parallel()

	// Create Paillier group with known order
	p, err := num.NPlus().FromUint64(7)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)

	original, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Serialise through PaillierGroupKnownOrder interface
	var group = original

	data, err := serde.MarshalCBOR(group)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize back to PaillierGroupKnownOrder interface
	decoded, err := serde.UnmarshalCBOR[znstar.PaillierGroupKnownOrder](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify modulus and order match
	require.True(t, original.Modulus().Equal(decoded.Modulus()))
	require.False(t, original.Order().IsUnknown())
	require.False(t, decoded.Order().IsUnknown())
	require.True(t, original.Order().Equal(decoded.Order()))

	// Verify N matches
	require.True(t, original.N().Equal(decoded.N()))

	// Test arithmetic is preserved
	require.NotNil(t, original.Arithmetic())
	require.NotNil(t, decoded.Arithmetic())

	// Create units and verify operations work
	zmod1 := original.AmbientGroup()
	u1, err := zmod1.FromUint64(100)
	require.NoError(t, err)
	unit1, err := original.FromUint(u1)
	require.NoError(t, err)

	zmod2 := decoded.AmbientGroup()
	u2, err := zmod2.FromUint64(100)
	require.NoError(t, err)
	unit2, err := decoded.FromUint(u2)
	require.NoError(t, err)

	// Test operations
	result1 := unit1.Square()
	result2 := unit2.Square()
	require.True(t, result1.Value().Equal(result2.Value()) == ct.True)
}

// Test PaillierGroup (unknown order) interface serialisation
func TestPaillierGroup_InterfaceSerialization_Unknown(t *testing.T) {
	t.Parallel()

	// Create Paillier group with unknown order
	n, err := num.NPlus().FromUint64(77) // 7 * 11
	require.NoError(t, err)
	n2 := n.Mul(n)

	original, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	require.NoError(t, err)

	// Serialise through PaillierGroup interface
	var group = original

	data, err := serde.MarshalCBOR(group)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize back to PaillierGroup interface
	decoded, err := serde.UnmarshalCBOR[znstar.PaillierGroup](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify properties
	require.True(t, original.Modulus().Equal(decoded.Modulus()))
	require.True(t, original.N().Equal(decoded.N()))
	require.True(t, original.Order().IsUnknown())
	require.True(t, decoded.Order().IsUnknown())
}

// Test round-trip serialisation for all Unit types
func TestUnit_RoundTrip_AllTypes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		createUnit   func() (znstar.Unit, error)
		unknownOrder bool
	}{
		{
			name: "RSA_UnknownOrder",
			createUnit: func() (znstar.Unit, error) {
				n, _ := num.NPlus().FromUint64(143)
				g, err := znstar.NewRSAGroupOfUnknownOrder(n)
				if err != nil {
					return nil, err
				}
				zmod := g.AmbientGroup()
				u, _ := zmod.FromUint64(5)
				return g.FromUint(u)
			},
			unknownOrder: true,
		},
		{
			name: "RSA_KnownOrder",
			createUnit: func() (znstar.Unit, error) {
				p, _ := num.NPlus().FromUint64(11)
				q, _ := num.NPlus().FromUint64(13)
				g, err := znstar.NewRSAGroup(p, q)
				if err != nil {
					return nil, err
				}
				zmod := g.AmbientGroup()
				u, _ := zmod.FromUint64(5)
				return g.FromUint(u)
			},
			unknownOrder: false,
		},
		{
			name: "Paillier_KnownOrder",
			createUnit: func() (znstar.Unit, error) {
				p, _ := num.NPlus().FromUint64(7)
				q, _ := num.NPlus().FromUint64(11)
				g, err := znstar.NewPaillierGroup(p, q)
				if err != nil {
					return nil, err
				}
				zmod := g.AmbientGroup()
				u, _ := zmod.FromUint64(100)
				return g.FromUint(u)
			},
			unknownOrder: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Create unit
			original, err := tc.createUnit()
			require.NoError(t, err)
			require.Equal(t, tc.unknownOrder, original.IsUnknownOrder())

			// Marshal through Unit interface
			data, err := serde.MarshalCBOR(original)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal back to Unit interface
			decoded, err := serde.UnmarshalCBOR[znstar.Unit](data)
			require.NoError(t, err)
			require.NotNil(t, decoded)

			// Verify properties
			require.Equal(t, tc.unknownOrder, decoded.IsUnknownOrder())
			require.True(t, original.Value().Equal(decoded.Value()) == ct.True)
			require.True(t, original.Modulus().Equal(decoded.Modulus()))

			// Verify order matches
			require.Equal(t, original.Group().Order().IsUnknown(), decoded.Group().Order().IsUnknown())
			if !tc.unknownOrder {
				require.True(t, original.Group().Order().Equal(decoded.Group().Order()))
			}
		})
	}
}

// Test error handling with invalid CBOR data
func TestCBOR_InvalidData_znstar(t *testing.T) {
	t.Parallel()

	t.Run("Unit_InvalidData", func(t *testing.T) {
		t.Parallel()
		_, err := serde.UnmarshalCBOR[znstar.Unit]([]byte{0x00})
		require.Error(t, err)
	})

	t.Run("UnitGroup_InvalidData", func(t *testing.T) {
		t.Parallel()
		_, err := serde.UnmarshalCBOR[znstar.UnitGroup]([]byte{0x00})
		require.Error(t, err)
	})
}

// Test ForgetOrder/LearnOrder round-trip with serialisation
func TestUnit_CBOR_OrderConversion(t *testing.T) {
	t.Parallel()

	// Create RSA group with known order
	p, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(13)
	require.NoError(t, err)

	knownGroup, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Create a unit with known order
	zmod := knownGroup.AmbientGroup()
	u, err := zmod.FromUint64(5)
	require.NoError(t, err)
	unitKnown, err := knownGroup.FromUint(u)
	require.NoError(t, err)
	require.False(t, unitKnown.IsUnknownOrder())

	// Serialise known order unit
	dataKnown, err := serde.MarshalCBOR(unitKnown)
	require.NoError(t, err)

	// Forget the order
	unitUnknown := unitKnown.ForgetOrder()
	require.True(t, unitUnknown.IsUnknownOrder())

	// Serialise unknown order unit
	dataUnknown, err := serde.MarshalCBOR(unitUnknown)
	require.NoError(t, err)

	// Data should be different (different tags/structures)
	require.NotEqual(t, dataKnown, dataUnknown)

	// Deserialize both
	decodedKnown, err := serde.UnmarshalCBOR[znstar.Unit](dataKnown)
	require.NoError(t, err)
	require.False(t, decodedKnown.IsUnknownOrder())

	decodedUnknown, err := serde.UnmarshalCBOR[znstar.Unit](dataUnknown)
	require.NoError(t, err)
	require.True(t, decodedUnknown.IsUnknownOrder())

	// Values should match
	require.True(t, unitKnown.Value().Equal(decodedKnown.Value()) == ct.True)
	require.True(t, unitUnknown.Value().Equal(decodedUnknown.Value()) == ct.True)
	require.True(t, decodedKnown.Value().Equal(decodedUnknown.Value()) == ct.True)
}
