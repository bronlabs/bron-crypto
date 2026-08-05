package trusted_dealer_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/keygen/trusted_dealer"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func TestDealRandomEncryptsRawMSPShareComponents(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	thresholdAccessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	accessStructure, err := cnf.ConvertToCNF(thresholdAccessStructure)
	require.NoError(t, err)

	shards, publicKey, err := trusted_dealer.DealRandom(curve, accessStructure, 1024, pcg.NewRandomised())
	require.NoError(t, err)
	require.Equal(t, shareholders.Size(), shards.Size())

	for holderID, holderShard := range shards.Iter() {
		holderShard = ntu.CBORRoundTrip(t, holderShard)
		require.False(t, holderShard.MSP().IsIdeal())
		require.True(t, holderShard.PublicKeyValue().Equal(publicKey.Value()))
		require.Equal(t, shareholders.Size()-1, holderShard.PaillierPublicKeys().Size())
		require.Equal(t, shareholders.Size()-1, holderShard.EncryptedShares().Size())
		require.False(t, holderShard.PaillierPublicKeys().ContainsKey(holderID))
		require.False(t, holderShard.EncryptedShares().ContainsKey(holderID))

		for peerID, peerPublicKey := range holderShard.PaillierPublicKeys().Iter() {
			peerShard, ok := shards.Get(peerID)
			require.True(t, ok)
			require.True(t, peerPublicKey.Equal(peerShard.PaillierSecretKey().Public()))

			peerCiphertexts, ok := holderShard.EncryptedShares().Get(peerID)
			require.True(t, ok)
			expectedComponents := peerShard.Share().Value()
			require.Len(t, peerCiphertexts, len(expectedComponents))
			require.Greater(t, len(peerCiphertexts), 1)
			for i, peerCiphertext := range peerCiphertexts {
				plaintext, err := peerShard.PaillierSecretKey().Decrypt(peerCiphertext)
				require.NoError(t, err)
				plaintextBytes := plaintext.Value().Big().Bytes()
				if len(plaintextBytes) == 0 {
					plaintextBytes = []byte{0}
				}
				decryptedComponent, err := curve.ScalarField().FromWideBytes(plaintextBytes)
				require.NoError(t, err)
				require.True(t, decryptedComponent.Equal(expectedComponents[i]),
					"holder %d stored the wrong component %d for peer %d", holderID, i, peerID)
			}
		}
	}

	holderShard, ok := shards.Get(1)
	require.True(t, ok)
	malformedEncryptedShares := hashmap.NewComparable[sharing.ID, []*paillier.Ciphertext]()
	for peerID, ciphertexts := range holderShard.EncryptedShares().Iter() {
		ciphertexts = slices.Clone(ciphertexts)
		if peerID == 2 {
			require.Greater(t, len(ciphertexts), 1)
			ciphertexts = ciphertexts[:len(ciphertexts)-1]
		}
		malformedEncryptedShares.Put(peerID, ciphertexts)
	}
	auxInfo, err := lindell17.NewAuxiliaryInfo(
		holderShard.PaillierSecretKey(),
		holderShard.PaillierPublicKeys(),
		malformedEncryptedShares.Freeze(),
	)
	require.NoError(t, err)
	_, err = lindell17.NewShard(&holderShard.BaseShard, auxInfo)
	require.ErrorIs(t, err, lindell17.ErrInvalidArgument)
	require.ErrorContains(t, err, "component count")
}

func TestDealRandomRejectsZeroPaillierKeyLength(t *testing.T) {
	t.Parallel()

	shareholders := sharing.NewOrdinalShareholderSet(2)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	_, _, err = trusted_dealer.DealRandom(k256.NewCurve(), accessStructure, 0, pcg.NewRandomised())
	require.ErrorIs(t, err, trusted_dealer.ErrInvalidArgument)
}

func TestDealRandomStoresNoUnqualifiedPeerMaterial(t *testing.T) {
	t.Parallel()

	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(3, shareholders)
	require.NoError(t, err)

	shards, _, err := trusted_dealer.DealRandom(k256.NewCurve(), accessStructure, 1024, pcg.NewRandomised())
	require.NoError(t, err)
	for _, shard := range shards.Iter() {
		require.Zero(t, shard.PaillierPublicKeys().Size())
		require.Zero(t, shard.EncryptedShares().Size())
	}
}

func TestLindell17ConstructorsRejectZeroValueNestedMaterial(t *testing.T) {
	t.Parallel()

	shareholders := sharing.NewOrdinalShareholderSet(2)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	shards, _, err := trusted_dealer.DealRandom(k256.NewCurve(), accessStructure, 1024, pcg.NewRandomised())
	require.NoError(t, err)
	holderShard, ok := shards.Get(1)
	require.True(t, ok)
	peerCiphertexts, ok := holderShard.EncryptedShares().Get(2)
	require.True(t, ok)
	peerPublicKey, ok := holderShard.PaillierPublicKeys().Get(2)
	require.True(t, ok)

	emptyPublicKeys := hashmap.NewComparable[sharing.ID, *paillier.PublicKey]().Freeze()
	emptyCiphertexts := hashmap.NewComparable[sharing.ID, []*paillier.Ciphertext]().Freeze()
	require.NotPanics(t, func() {
		_, err = lindell17.NewAuxiliaryInfo(new(paillier.SecretKey), emptyPublicKeys, emptyCiphertexts)
	})
	require.ErrorIs(t, err, lindell17.ErrInvalidArgument)

	invalidPublicKeys := hashmap.NewComparable[sharing.ID, *paillier.PublicKey]()
	invalidPublicKeys.Put(2, new(paillier.PublicKey))
	validCiphertexts := hashmap.NewComparable[sharing.ID, []*paillier.Ciphertext]()
	validCiphertexts.Put(2, peerCiphertexts)
	require.NotPanics(t, func() {
		_, err = lindell17.NewAuxiliaryInfo(holderShard.PaillierSecretKey(), invalidPublicKeys.Freeze(), validCiphertexts.Freeze())
	})
	require.ErrorIs(t, err, lindell17.ErrInvalidArgument)

	validPublicKeys := hashmap.NewComparable[sharing.ID, *paillier.PublicKey]()
	validPublicKeys.Put(2, peerPublicKey)
	invalidCiphertexts := hashmap.NewComparable[sharing.ID, []*paillier.Ciphertext]()
	invalidCiphertexts.Put(2, []*paillier.Ciphertext{new(paillier.Ciphertext)})
	require.NotPanics(t, func() {
		_, err = lindell17.NewAuxiliaryInfo(holderShard.PaillierSecretKey(), validPublicKeys.Freeze(), invalidCiphertexts.Freeze())
	})
	require.ErrorIs(t, err, lindell17.ErrInvalidArgument)

	validAuxInfo, err := lindell17.NewAuxiliaryInfo(
		holderShard.PaillierSecretKey(),
		holderShard.PaillierPublicKeys(),
		holderShard.EncryptedShares(),
	)
	require.NoError(t, err)
	require.NotPanics(t, func() {
		_, err = lindell17.NewShard(new(mpc.BaseShard[*k256.Point, *k256.Scalar]), validAuxInfo)
	})
	require.ErrorIs(t, err, lindell17.ErrInvalidArgument)
	require.NotPanics(t, func() {
		_, err = lindell17.NewShard(&holderShard.BaseShard, new(lindell17.AuxiliaryInfo))
	})
	require.ErrorIs(t, err, lindell17.ErrInvalidArgument)
}
