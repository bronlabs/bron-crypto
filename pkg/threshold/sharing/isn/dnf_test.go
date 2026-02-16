package isn_test

import (
	"bytes"
	mrand "math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn"
)

func TestDNFSanity(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	// Create DNF access structure: {1,2} OR {2,3,4}
	minimalSets := []ds.Set[sharing.ID]{
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](2, 3, 4).Freeze(),
	}
	ac, err := sharing.NewDNFAccessStructure(minimalSets...)
	require.NoError(t, err)

	scheme := isn.NewDNFScheme(group, ac)
	require.NotNil(t, scheme)
	require.Equal(t, isn.DNFName, scheme.Name())

	secret := isn.NewSecret(group.FromUint64(42))
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)
	require.NotNil(t, out)

	shares := out.Shares()
	require.Equal(t, 4, shares.Size())

	// Verify shares have sparse maps (parties only have entries for clauses they're in)
	// Party 1 is in {1,2} only
	// Party 2 is in both {1,2} and {2,3,4}
	// Parties 3,4 are in {2,3,4} only
	for id, share := range shares.Iter() {
		if id == 2 {
			require.Len(t, share.Value(), 2, "party 2 should have 2 entries (in both clauses)")
		} else {
			require.Len(t, share.Value(), 1, "parties 1,3,4 should have 1 entry (in one clause)")
		}
	}

	// Reconstruct with all shares
	reconstructed, err := scheme.Reconstruct(shares.Values()...)
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed))
}

func TestDNFDeal(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	// Access structure: {1,2} OR {3,4,5}
	ac, err := sharing.NewDNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4, 5).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewDNFScheme(group, ac)

	t.Run("zero secret", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.Zero())
		out, err := scheme.Deal(secret, pcg.NewRandomised())
		require.NoError(t, err)

		reconstructed, err := scheme.Reconstruct(out.Shares().Values()...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("one secret", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.One())
		out, err := scheme.Deal(secret, pcg.NewRandomised())
		require.NoError(t, err)

		reconstructed, err := scheme.Reconstruct(out.Shares().Values()...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("random secret", func(t *testing.T) {
		t.Parallel()
		val, err := group.Random(pcg.NewRandomised())
		require.NoError(t, err)
		secret := isn.NewSecret(val)

		out, err := scheme.Deal(secret, pcg.NewRandomised())
		require.NoError(t, err)

		reconstructed, err := scheme.Reconstruct(out.Shares().Values()...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("nil secret", func(t *testing.T) {
		t.Parallel()
		out, err := scheme.Deal(nil, pcg.NewRandomised())
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrIsNil)
		require.Nil(t, out)
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(42))
		out, err := scheme.Deal(secret, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrIsNil)
		require.Nil(t, out)
	})

	t.Run("short prng", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(42))
		out, err := scheme.Deal(secret, bytes.NewReader([]byte{1}))
		require.Error(t, err)
		require.Nil(t, out)
	})
}

func TestDNFDealRandom(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()
	ac, err := sharing.NewDNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](2, 3).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewDNFScheme(group, ac)

	t.Run("valid random generation", func(t *testing.T) {
		t.Parallel()
		out, err := scheme.DealRandom(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, 3, out.Shares().Size())
	})

	t.Run("multiple generations produce different secrets", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()

		out1, err := scheme.DealRandom(prng)
		require.NoError(t, err)

		out2, err := scheme.DealRandom(prng)
		require.NoError(t, err)

		// Reconstruct both and verify they're different
		secret1, err := scheme.Reconstruct(out1.Shares().Values()...)
		require.NoError(t, err)

		secret2, err := scheme.Reconstruct(out2.Shares().Values()...)
		require.NoError(t, err)

		require.False(t, secret1.Equal(secret2), "consecutive random secrets should differ")
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		out, err := scheme.DealRandom(nil)
		require.Error(t, err)
		require.Nil(t, out)
	})
}

func TestDNFReconstruct_Authorization(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	// Access structure: {1,2} OR {2,3,4}
	// Authorized: {1,2}, {2,3,4}, {1,2,3}, {1,2,4}, {1,2,3,4}, etc.
	// Unauthorised: {1}, {2}, {3}, {1,3}, {1,4}, {3,4}, etc.
	ac, err := sharing.NewDNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](2, 3, 4).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewDNFScheme(group, ac)
	secret := isn.NewSecret(group.FromUint64(12345))

	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	sharesMap := make(map[sharing.ID]*isn.Share[*k256.Scalar])
	for id, share := range out.Shares().Iter() {
		sharesMap[id] = share
	}

	t.Run("first minimal qualified set", func(t *testing.T) {
		t.Parallel()
		// {1,2} should reconstruct
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[1],
			sharesMap[2],
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("second minimal qualified set", func(t *testing.T) {
		t.Parallel()
		// {2,3,4} should reconstruct
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[2],
			sharesMap[3],
			sharesMap[4],
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("superset of minimal qualified set", func(t *testing.T) {
		t.Parallel()
		// {1,2,3,4} should reconstruct
		reconstructed, err := scheme.Reconstruct(out.Shares().Values()...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("unauthorised single party", func(t *testing.T) {
		t.Parallel()
		// {1} is unauthorised
		shares := []*isn.Share[*k256.Scalar]{sharesMap[1]}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})

	t.Run("unauthorised subset", func(t *testing.T) {
		t.Parallel()
		// {3,4} is unauthorised (subset of {2,3,4} but not qualified)
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[3],
			sharesMap[4],
		}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})

	t.Run("unauthorised disjoint set", func(t *testing.T) {
		t.Parallel()
		// {1,3} is unauthorised
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[1],
			sharesMap[3],
		}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})

	t.Run("nil share in authorized set", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[1],
			nil,
		}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
	})
}

func TestDNFShareHomomorphism(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()
	ac, err := sharing.NewDNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](2, 3).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewDNFScheme(group, ac)

	// Create two secrets
	secret1 := isn.NewSecret(group.FromUint64(100))
	secret2 := isn.NewSecret(group.FromUint64(200))

	// Deal both secrets with same PRNG state for determinism
	seed1, seed2 := mrand.Uint64(), mrand.Uint64()

	out1, err := scheme.Deal(secret1, pcg.New(seed1, seed2))
	require.NoError(t, err)

	out2, err := scheme.Deal(secret2, pcg.New(seed1, seed2))
	require.NoError(t, err)

	// Combine shares homomorphically
	combinedShares := make(map[sharing.ID]*isn.Share[*k256.Scalar])
	for id, share1 := range out1.Shares().Iter() {
		share2, ok := out2.Shares().Get(id)
		require.True(t, ok)
		combinedShares[id] = share1.Op(share2)
	}

	// Reconstruct from combined shares
	var combinedSlice []*isn.Share[*k256.Scalar]
	for _, share := range combinedShares {
		combinedSlice = append(combinedSlice, share)
	}
	reconstructed, err := scheme.Reconstruct(combinedSlice...)
	require.NoError(t, err)

	// Expected secret is secret1 + secret2
	expectedSecret := isn.NewSecret(secret1.Value().Op(secret2.Value()))
	require.True(t, expectedSecret.Equal(reconstructed))
}

func TestDNF_BLS12381(t *testing.T) {
	t.Parallel()

	// Test with a different group (BLS12-381 scalar field)
	group := bls12381.NewScalarField()

	ac, err := sharing.NewDNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2, 3).Freeze(),
		hashset.NewComparable[sharing.ID](4, 5).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewDNFScheme(group, ac)

	secret := isn.NewSecret(group.FromUint64(999))
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	// Verify reconstruction with first minimal qualified set
	sharesMap := make(map[sharing.ID]*isn.Share[*bls12381.Scalar])
	for id, share := range out.Shares().Iter() {
		sharesMap[id] = share
	}

	shares := []*isn.Share[*bls12381.Scalar]{
		sharesMap[1],
		sharesMap[2],
		sharesMap[3],
	}
	reconstructed, err := scheme.Reconstruct(shares...)
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed))
}
