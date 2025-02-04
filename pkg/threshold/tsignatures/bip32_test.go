package tsignatures_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Bip32TestVector2(t *testing.T) {
	curve := k256.NewCurve()
	prng := crand.Reader

	chainCodeHex := "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
	chainCode, err := hex.DecodeString(chainCodeHex)
	require.NoError(t, err)

	skHex := "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
	skBytes, err := hex.DecodeString(skHex)
	require.NoError(t, err)
	sk, err := curve.ScalarField().Element().SetBytes(skBytes)
	require.NoError(t, err)
	pk := curve.ScalarBaseMult(sk)

	dealer, err := shamir.NewDealer(2, 3, curve)
	require.NoError(t, err)

	shares, err := dealer.Split(sk, prng)
	require.NoError(t, err)

	aliceMasterShare := &tsignatures.ExtendedSigningKeyShare{
		SigningKeyShare: tsignatures.SigningKeyShare{
			Share:     shares[0].Value,
			PublicKey: pk,
		},
	}
	copy(aliceMasterShare.ChainCode[:], chainCode)

	bobMasterShare := &tsignatures.ExtendedSigningKeyShare{
		SigningKeyShare: tsignatures.SigningKeyShare{
			Share:     shares[1].Value,
			PublicKey: pk,
		},
	}
	copy(bobMasterShare.ChainCode[:], chainCode)

	charlieMasterShare := &tsignatures.ExtendedSigningKeyShare{
		SigningKeyShare: tsignatures.SigningKeyShare{
			Share:     shares[2].Value,
			PublicKey: pk,
		},
	}
	copy(charlieMasterShare.ChainCode[:], chainCode)

	aliceChildShare := tsignatures.DeriveBip32(aliceMasterShare, []uint32{0})
	bobChildShare := tsignatures.DeriveBip32(bobMasterShare, []uint32{0})
	charlieChildShare := tsignatures.DeriveBip32(charlieMasterShare, []uint32{0})

	childSk, err := dealer.Combine(&shamir.Share{Id: shares[0].Id, Value: aliceChildShare.Share}, &shamir.Share{Id: shares[1].Id, Value: bobChildShare.Share}, &shamir.Share{Id: shares[2].Id, Value: charlieChildShare.Share})
	require.NoError(t, err)
	childPk := curve.ScalarBaseMult(childSk)

	expectedChildSecretKeyHex := "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
	expectedChildPublicKeyHex := "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
	expectedChildChainCodeHex := "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"

	require.Equal(t, expectedChildSecretKeyHex, hex.EncodeToString(childSk.Bytes()))
	require.Equal(t, expectedChildPublicKeyHex, hex.EncodeToString(childPk.ToAffineCompressed()))

	require.Equal(t, expectedChildPublicKeyHex, hex.EncodeToString(aliceChildShare.PublicKey.ToAffineCompressed()))
	require.Equal(t, expectedChildPublicKeyHex, hex.EncodeToString(bobChildShare.PublicKey.ToAffineCompressed()))
	require.Equal(t, expectedChildPublicKeyHex, hex.EncodeToString(charlieChildShare.PublicKey.ToAffineCompressed()))

	require.Equal(t, expectedChildChainCodeHex, hex.EncodeToString(aliceChildShare.ChainCode[:]))
	require.Equal(t, expectedChildChainCodeHex, hex.EncodeToString(bobChildShare.ChainCode[:]))
	require.Equal(t, expectedChildChainCodeHex, hex.EncodeToString(charlieChildShare.ChainCode[:]))
}
