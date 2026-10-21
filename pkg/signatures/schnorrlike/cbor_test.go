package schnorrlike_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/bip340"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
)

func TestKeyAndSignatureSerialization(t *testing.T) {
	t.Parallel()
	privateKey, err := bip340.NewPrivateKey(k256.NewScalarField().FromUint64(3))
	require.NoError(t, err)
	publicKey := privateKey.PublicKey()
	scheme := bip340.NewSchemeWithAux([bip340.AuxSizeBytes]byte{})
	signer, err := scheme.Signer(privateKey)
	require.NoError(t, err)
	message := []byte("serialised data remains usable")
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	data, err := serde.MarshalCBOR(*privateKey)
	require.NoError(t, err)
	decodedPrivateKey, err := serde.UnmarshalCBOR[*bip340.PrivateKey](data)
	require.NoError(t, err)
	require.True(t, privateKey.Equal(decodedPrivateKey))
	data, err = serde.MarshalCBOR(publicKey)
	require.NoError(t, err)
	decodedPublicKey, err := serde.UnmarshalCBOR[*bip340.PublicKey](data)
	require.NoError(t, err)
	require.True(t, publicKey.Equal(decodedPublicKey))
	data, err = serde.MarshalCBOR(signature)
	require.NoError(t, err)
	decodedSignature, err := serde.UnmarshalCBOR[*bip340.Signature](data)
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(decodedSignature, decodedPublicKey, message))
}

func TestPrivateKeyCBORPallas(t *testing.T) {
	t.Parallel()
	privateKey, err := mina.NewPrivateKey(pasta.NewPallasScalarField().FromUint64(3))
	require.NoError(t, err)
	for name, value := range map[string]any{"pointer": privateKey, "value": *privateKey} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := serde.MarshalCBOR(value)
			require.NoError(t, err)
			decoded, err := serde.UnmarshalCBOR[*mina.PrivateKey](data)
			require.NoError(t, err)
			require.True(t, privateKey.Equal(decoded))
		})
	}
}

func TestPrivateKeyCBORRejectsInvalidComponents(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	group := k256.NewCurve()
	value := field.FromUint64(3)
	point := group.ScalarBaseMul(value)
	for name, tc := range map[string]struct {
		scalar *k256.Scalar
		point  *k256.Point
		want   error
	}{
		"missing_scalar":      {nil, point, signatures.ErrInvalidArgument},
		"zero_scalar":         {field.Zero(), point, signatures.ErrFailed},
		"missing_public_key":  {value, nil, signatures.ErrInvalidArgument},
		"identity_public_key": {value, group.OpIdentity(), signatures.ErrFailed},
		"mismatched_keys":     {field.FromUint64(4), point, signatures.ErrInvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := serde.MarshalCBOR(struct {
				SK *k256.Scalar `cbor:"privateKey"`
				PK *k256.Point  `cbor:"publicKey"`
			}{SK: tc.scalar, PK: tc.point})
			require.NoError(t, err)
			_, err = serde.UnmarshalCBOR[*bip340.PrivateKey](data)
			require.True(t, errs.Is(err, tc.want), "%v", err)
		})
	}
}

func TestPrivateKeyCBORRejectsNull(t *testing.T) {
	t.Parallel()
	var privateKey bip340.PrivateKey
	err := privateKey.UnmarshalCBOR([]byte{0xf6})
	require.True(t, errs.Is(err, signatures.ErrInvalidArgument))
}
