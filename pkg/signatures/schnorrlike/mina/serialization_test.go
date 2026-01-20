package mina //nolint:testpackage // to test unexported identifiers

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/base58"
)

// TestSignatureSerializationFormat verifies that our signature serialisation
// matches the o1js/mina-signer format: (R.x || s) in little-endian, 64 bytes total.
func TestSignatureSerializationFormat(t *testing.T) {
	t.Parallel()

	// Use a known signature from our test vectors
	// Payment test vector 1, devnet:
	// field:  "3925887987173883783388058255268083382298769764463609405200521482763932632383"
	// scalar: "445615701481226398197189554290689546503290167815530435382795701939759548136"
	fieldStr := "3925887987173883783388058255268083382298769764463609405200521482763932632383"
	scalarStr := "445615701481226398197189554290689546503290167815530435382795701939759548136"

	// Parse field (R.x) as big integer
	rxBigInt, ok := new(big.Int).SetString(fieldStr, 10)
	require.True(t, ok)

	// Parse scalar (s) as big integer
	sBigInt, ok := new(big.Int).SetString(scalarStr, 10)
	require.True(t, ok)

	// Convert big integers to 32-byte big-endian slices
	rxBytesBE := make([]byte, 32)
	rxBigInt.FillBytes(rxBytesBE)

	sBytesBE := make([]byte, 32)
	sBigInt.FillBytes(sBytesBE)

	// Create field element for R.x
	rx, err := group.BaseField().FromBytes(rxBytesBE)
	require.NoError(t, err)

	// Create R point from x-coordinate with even y (as per Mina spec)
	R, err := group.FromAffineX(rx, false)
	require.NoError(t, err)

	// Create scalar for s
	s, err := sf.FromBytes(sBytesBE)
	require.NoError(t, err)

	// Create signature
	sig := &Signature{R: R, S: s}

	// Serialise signature
	serialised, err := SerializeSignature(sig)
	require.NoError(t, err)
	assert.Len(t, serialised, 64, "serialised signature should be 64 bytes")

	// Verify the first 32 bytes are R.x in little-endian
	// o1js uses little-endian byte order
	rxBytesLE := serialised[:32]
	for i := range 32 {
		assert.Equal(t, rxBytesBE[31-i], rxBytesLE[i],
			"R.x byte %d: expected %02x (from BE position %d), got %02x",
			i, rxBytesBE[31-i], 31-i, rxBytesLE[i])
	}

	// Verify the second 32 bytes are s in little-endian
	sBytesLE := serialised[32:]
	for i := range 32 {
		assert.Equal(t, sBytesBE[31-i], sBytesLE[i],
			"s byte %d: expected %02x (from BE position %d), got %02x",
			i, sBytesBE[31-i], 31-i, sBytesLE[i])
	}

	// Test deserialization round-trip
	deserialized, err := DeserializeSignature(serialised)
	require.NoError(t, err)

	// Verify R.x matches
	deserializedRx, err := deserialized.R.AffineX()
	require.NoError(t, err)
	assert.Equal(t, fieldStr, deserializedRx.String(), "deserialized R.x should match")

	// Verify s matches
	assert.Equal(t, scalarStr, deserialized.S.String(), "deserialized s should match")
}

// TestSignatureBase58Encoding verifies that signature base58 encoding
// uses the correct version prefix (0x9A) and can round-trip correctly.
func TestSignatureBase58Encoding(t *testing.T) {
	t.Parallel()

	// Use the same test vector
	fieldStr := "3925887987173883783388058255268083382298769764463609405200521482763932632383"
	scalarStr := "445615701481226398197189554290689546503290167815530435382795701939759548136"

	rxBigInt, _ := new(big.Int).SetString(fieldStr, 10)
	sBigInt, _ := new(big.Int).SetString(scalarStr, 10)

	rxBytesBE := make([]byte, 32)
	rxBigInt.FillBytes(rxBytesBE)
	sBytesBE := make([]byte, 32)
	sBigInt.FillBytes(sBytesBE)

	rx, err := group.BaseField().FromBytes(rxBytesBE)
	require.NoError(t, err)
	R, err := group.FromAffineX(rx, false)
	require.NoError(t, err)
	s, err := sf.FromBytes(sBytesBE)
	require.NoError(t, err)

	sig := &Signature{R: R, S: s}

	// Encode to base58
	encoded, err := EncodeSignature(sig)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify version prefix by decoding
	data, version, err := base58.CheckDecode(encoded)
	require.NoError(t, err)
	assert.Equal(t, SignatureBase58VersionPrefix, version,
		"signature should use version prefix 0x9A")
	assert.Len(t, data, 64, "signature payload should be 64 bytes")

	// Decode and verify round-trip
	decoded, err := DecodeSignature(encoded)
	require.NoError(t, err)

	decodedRx, _ := decoded.R.AffineX()
	assert.Equal(t, fieldStr, decodedRx.String())
	assert.Equal(t, scalarStr, decoded.S.String())
}

// TestSignatureSerializationAllTestVectors verifies serialisation for all test vectors.
func TestSignatureSerializationAllTestVectors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		field  string
		scalar string
	}{
		{
			name:   "payment_0_devnet",
			field:  "3925887987173883783388058255268083382298769764463609405200521482763932632383",
			scalar: "445615701481226398197189554290689546503290167815530435382795701939759548136",
		},
		{
			name:   "payment_0_mainnet",
			field:  "2290465734865973481454975811990842289349447524565721011257265781466170720513",
			scalar: "174718295375042423373378066296864207343460524320417038741346483351503066865",
		},
		{
			name:   "delegation_0_devnet",
			field:  "18603328765572408555868399359399411973012220541556204196884026585115374044583",
			scalar: "17076342019359061119005549736934690084415105419939473687106079907606137611470",
		},
		{
			name:   "string_0_devnet",
			field:  "11583775536286847540414661987230057163492736306749717851628536966882998258109",
			scalar: "14787360096063782022566783796923142259879388947509616216546009448340181956495",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Create signature from known values
			rxBigInt, ok := new(big.Int).SetString(tc.field, 10)
			require.True(t, ok)
			sBigInt, ok := new(big.Int).SetString(tc.scalar, 10)
			require.True(t, ok)

			rxBytesBE := make([]byte, 32)
			rxBigInt.FillBytes(rxBytesBE)
			sBytesBE := make([]byte, 32)
			sBigInt.FillBytes(sBytesBE)

			rx, err := group.BaseField().FromBytes(rxBytesBE)
			require.NoError(t, err)
			R, err := group.FromAffineX(rx, false)
			require.NoError(t, err)
			s, err := sf.FromBytes(sBytesBE)
			require.NoError(t, err)

			sig := &Signature{R: R, S: s}

			// Test serialise -> deserialize round-trip
			serialised, err := SerializeSignature(sig)
			require.NoError(t, err)
			assert.Len(t, serialised, 64)

			deserialized, err := DeserializeSignature(serialised)
			require.NoError(t, err)

			decodedRx, _ := deserialized.R.AffineX()
			assert.Equal(t, tc.field, decodedRx.String())
			assert.Equal(t, tc.scalar, deserialized.S.String())

			// Test base58 encode -> decode round-trip
			encoded, err := EncodeSignature(sig)
			require.NoError(t, err)

			decoded, err := DecodeSignature(encoded)
			require.NoError(t, err)

			decodedRx2, _ := decoded.R.AffineX()
			assert.Equal(t, tc.field, decodedRx2.String())
			assert.Equal(t, tc.scalar, decoded.S.String())
		})
	}
}

// TestSignatureSerializationByteOrder explicitly tests that we use little-endian.
func TestSignatureSerializationByteOrder(t *testing.T) {
	t.Parallel()

	// Create a signature with a simple known value for easy verification
	// R.x = 1, S = 2
	rxBigInt := big.NewInt(1)
	sBigInt := big.NewInt(2)

	rxBytesBE := make([]byte, 32)
	rxBigInt.FillBytes(rxBytesBE)
	sBytesBE := make([]byte, 32)
	sBigInt.FillBytes(sBytesBE)

	rx, err := group.BaseField().FromBytes(rxBytesBE)
	require.NoError(t, err)
	R, err := group.FromAffineX(rx, false)
	require.NoError(t, err)
	s, err := sf.FromBytes(sBytesBE)
	require.NoError(t, err)

	sig := &Signature{R: R, S: s}

	serialised, err := SerializeSignature(sig)
	require.NoError(t, err)

	// For R.x = 1 in little-endian, byte 0 should be 0x01, rest should be 0x00
	assert.Equal(t, byte(0x01), serialised[0], "R.x first byte (LE) should be 0x01")
	for i := 1; i < 32; i++ {
		assert.Equal(t, byte(0x00), serialised[i], "R.x byte %d should be 0x00", i)
	}

	// For S = 2 in little-endian, byte 32 should be 0x02, rest should be 0x00
	assert.Equal(t, byte(0x02), serialised[32], "S first byte (LE) should be 0x02")
	for i := 33; i < 64; i++ {
		assert.Equal(t, byte(0x00), serialised[i], "S byte %d should be 0x00", i)
	}
}

// TestSignedSignatureSerializationRoundTrip tests that signatures produced by
// actual signing can be serialised and deserialized correctly.
func TestSignedSignatureSerializationRoundTrip(t *testing.T) {
	t.Parallel()

	privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)
	publicKey, err := DecodePublicKey("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)

	scheme, err := NewScheme(TestNet, privateKey)
	require.NoError(t, err)

	signer, err := scheme.Signer(privateKey)
	require.NoError(t, err)

	verifier, err := scheme.Verifier()
	require.NoError(t, err)

	msg := new(ROInput).Init()
	msg.AddString("serialisation test message")

	// Sign the message
	sig, err := signer.Sign(msg)
	require.NoError(t, err)

	// Serialise to bytes
	serialised, err := SerializeSignature(sig)
	require.NoError(t, err)
	assert.Len(t, serialised, 64)

	// Deserialize
	deserialized, err := DeserializeSignature(serialised)
	require.NoError(t, err)

	// Verify the deserialized signature works
	err = verifier.Verify(deserialized, publicKey, msg)
	require.NoError(t, err, "deserialized signature should verify")

	// Also test base58 round-trip
	encoded, err := EncodeSignature(sig)
	require.NoError(t, err)

	decoded, err := DecodeSignature(encoded)
	require.NoError(t, err)

	err = verifier.Verify(decoded, publicKey, msg)
	require.NoError(t, err, "base58 decoded signature should verify")
}
