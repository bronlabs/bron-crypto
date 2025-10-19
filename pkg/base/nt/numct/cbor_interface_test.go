package numct

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// TestModulusInterface_TagBasedCBOR tests that we can serialise/deserialize
// Modulus interfaces directly using CBOR tags
func TestModulusInterface_TagBasedCBOR(t *testing.T) {
	// Create various modulus types
	n := NewNat(101) // Prime number

	testCases := []struct {
		name       string
		createMod  func() Modulus
		expectType string
	}{
		{
			name: "ModulusOddPrime",
			createMod: func() Modulus {
				mod, ok := NewModulusOddPrime(n)
				require.Equal(t, ct.True, ok)
				return mod
			},
			expectType: "*numct.ModulusOddPrime",
		},
		{
			name: "ModulusOdd",
			createMod: func() Modulus {
				mod, ok := NewModulusOdd(n)
				require.Equal(t, ct.True, ok)
				return mod
			},
			expectType: "*numct.ModulusOdd",
		},
		{
			name: "ModulusBasic",
			createMod: func() Modulus {
				return newModulusBasic(n)
			},
			expectType: "*numct.ModulusBasic",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create the modulus as an interface
			var original Modulus = tc.createMod()

			data, err := serde.MarshalCBOR(original)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Deserialize back
			deserialized, err := serde.UnmarshalCBOR[Modulus](data)
			require.NoError(t, err)
			require.NotNil(t, deserialized)

			// Check the type is preserved
			actualType := reflect.TypeOf(deserialized).String()
			require.Equal(t, tc.expectType, actualType, "Type should be preserved")

			// Check the value is preserved
			require.Equal(t, ct.True, original.Nat().Equal(deserialized.Nat()))
		})
	}
}

// TestModulusInterface_SliceOfInterfaces tests serialising slices of interfaces
func TestModulusInterface_SliceOfInterfaces(t *testing.T) {
	// Create a slice of different modulus types
	var moduli []Modulus

	// Add various types
	n1 := NewNat(103)
	mod1, _ := NewModulusOddPrime(n1)
	moduli = append(moduli, mod1)

	n2 := NewNat(105) // Odd but not prime (3*5*7)
	mod2, _ := NewModulusOdd(n2)
	moduli = append(moduli, mod2)

	n3 := NewNat(108)
	mod3, _ := NewModulus(n3)
	moduli = append(moduli, mod3)

	// Serialise the slice of interfaces directly
	data, err := serde.MarshalCBOR(moduli)
	require.NoError(t, err)

	// Deserialize back
	restored, err := serde.UnmarshalCBOR[[]Modulus](data)
	require.NoError(t, err)
	require.Len(t, restored, len(moduli))

	// Verify each element
	for i, original := range moduli {
		require.Equal(t, ct.True, original.Nat().Equal(restored[i].Nat()))
		// Types should match
		require.Equal(t, reflect.TypeOf(original), reflect.TypeOf(restored[i]))
	}
}
