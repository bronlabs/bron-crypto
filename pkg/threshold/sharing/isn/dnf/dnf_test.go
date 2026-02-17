package dnf_test

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
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn/dnf"
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

	scheme, err := dnf.NewFiniteScheme(group, ac)
	require.NoError(t, err)
	require.NotNil(t, scheme)
	require.Equal(t, dnf.Name, scheme.Name())

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
			require.Equal(t, 2, share.Value().Size(), "party 2 should have 2 entries (in both clauses)")
		} else {
			require.Equal(t, 1, share.Value().Size(), "parties 1,3,4 should have 1 entry (in one clause)")
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

	scheme, err := dnf.NewFiniteScheme(group, ac)
	require.NoError(t, err)

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

	scheme, err := dnf.NewFiniteScheme(group, ac)
	require.NoError(t, err)

	t.Run("valid random generation", func(t *testing.T) {
		t.Parallel()
		out, secret, err := scheme.DealRandom(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, out)
		require.NotNil(t, secret)
		require.Equal(t, 3, out.Shares().Size())
	})

	t.Run("multiple generations produce different secrets", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()

		out1, secret1, err := scheme.DealRandom(prng)
		require.NoError(t, err)

		_, secret2, err2 := scheme.DealRandom(prng)
		require.NoError(t, err2)

		// Verify consecutive random secrets differ
		require.False(t, secret1.Equal(secret2), "consecutive random secrets should differ")

		// Also verify reconstruction matches generated secrets
		reconstructed1, err3 := scheme.Reconstruct(out1.Shares().Values()...)
		require.NoError(t, err3)
		require.True(t, secret1.Equal(reconstructed1))
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		out, secret, err := scheme.DealRandom(nil)
		require.Error(t, err)
		require.Nil(t, out)
		require.Nil(t, secret)
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

	scheme, err := dnf.NewFiniteScheme(group, ac)
	require.NoError(t, err)
	secret := isn.NewSecret(group.FromUint64(12345))

	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	sharesMap := make(map[sharing.ID]*dnf.Share[*k256.Scalar])
	for id, share := range out.Shares().Iter() {
		sharesMap[id] = share
	}

	t.Run("first minimal qualified set", func(t *testing.T) {
		t.Parallel()
		// {1,2} should reconstruct
		shares := []*dnf.Share[*k256.Scalar]{
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
		shares := []*dnf.Share[*k256.Scalar]{
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
		shares := []*dnf.Share[*k256.Scalar]{sharesMap[1]}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})

	t.Run("unauthorised subset", func(t *testing.T) {
		t.Parallel()
		// {3,4} is unauthorised (subset of {2,3,4} but not qualified)
		shares := []*dnf.Share[*k256.Scalar]{
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
		shares := []*dnf.Share[*k256.Scalar]{
			sharesMap[1],
			sharesMap[3],
		}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})

	t.Run("nil share in authorized set", func(t *testing.T) {
		t.Parallel()
		shares := []*dnf.Share[*k256.Scalar]{
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

	scheme, err := dnf.NewFiniteScheme(group, ac)
	require.NoError(t, err)

	// Create two secrets
	secret1 := isn.NewSecret(group.FromUint64(100))
	secret2 := isn.NewSecret(group.FromUint64(200))

	seed1, seed2 := mrand.Uint64(), mrand.Uint64()

	out1, err := scheme.Deal(secret1, pcg.New(seed1, seed2))
	require.NoError(t, err)

	out2, err := scheme.Deal(secret2, pcg.New(seed1, seed2))
	require.NoError(t, err)

	// Combine shares homomorphically
	combinedShares := make(map[sharing.ID]*dnf.Share[*k256.Scalar])
	for id, share1 := range out1.Shares().Iter() {
		share2, ok := out2.Shares().Get(id)
		require.True(t, ok)
		combinedShares[id] = share1.Op(share2)
	}

	// Reconstruct from combined shares
	var combinedSlice []*dnf.Share[*k256.Scalar]
	for _, share := range combinedShares {
		combinedSlice = append(combinedSlice, share)
	}
	reconstructed, err := scheme.Reconstruct(combinedSlice...)
	require.NoError(t, err)

	// Expected secret is secret1 + secret2
	expectedSecret := isn.NewSecret(secret1.Value().Op(secret2.Value()))
	require.True(t, expectedSecret.Equal(reconstructed))
}

func TestDNFDealAndRevealDealerFunc(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()
	ac, err := sharing.NewDNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](2, 3).Freeze(),
	)
	require.NoError(t, err)

	scheme, err := dnf.NewFiniteScheme(group, ac)
	require.NoError(t, err)

	t.Run("deal and reveal dealer func", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(99999))

		out, dealerFunc, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, out)
		require.NotNil(t, dealerFunc)
		require.Equal(t, 3, out.Shares().Size())
		require.Equal(t, 3, len(dealerFunc))

		// Verify dealer func contains all shares
		for id, share := range out.Shares().Iter() {
			dfShare, ok := dealerFunc[id]
			require.True(t, ok)
			require.True(t, share.Equal(dfShare))
		}

		// Verify reconstruction works
		reconstructed, err := scheme.Reconstruct(out.Shares().Values()...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("nil secret", func(t *testing.T) {
		t.Parallel()
		out, dealerFunc, err := scheme.DealAndRevealDealerFunc(nil, pcg.NewRandomised())
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrIsNil)
		require.Nil(t, out)
		require.Nil(t, dealerFunc)
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(42))
		out, dealerFunc, err := scheme.DealAndRevealDealerFunc(secret, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrIsNil)
		require.Nil(t, out)
		require.Nil(t, dealerFunc)
	})
}

func TestDNFDealRandomAndRevealDealerFunc(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()
	ac, err := sharing.NewDNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](2, 3).Freeze(),
	)
	require.NoError(t, err)

	scheme, err := dnf.NewFiniteScheme(group, ac)
	require.NoError(t, err)

	t.Run("deal random and reveal dealer func", func(t *testing.T) {
		t.Parallel()

		out, secret, dealerFunc, err := scheme.DealRandomAndRevealDealerFunc(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, out)
		require.NotNil(t, secret)
		require.NotNil(t, dealerFunc)
		require.Equal(t, 3, out.Shares().Size())
		require.Equal(t, 3, len(dealerFunc))

		// Verify dealer func contains all shares
		for id, share := range out.Shares().Iter() {
			dfShare, ok := dealerFunc[id]
			require.True(t, ok)
			require.True(t, share.Equal(dfShare))
		}

		// Verify reconstruction works
		reconstructed, err := scheme.Reconstruct(out.Shares().Values()...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("multiple generations produce different secrets and dealer funcs", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()

		out1, secret1, dealerFunc1, err := scheme.DealRandomAndRevealDealerFunc(prng)
		require.NoError(t, err)

		_, secret2, dealerFunc2, err2 := scheme.DealRandomAndRevealDealerFunc(prng)
		require.NoError(t, err2)

		// Verify secrets differ
		require.False(t, secret1.Equal(secret2))

		// Verify dealer funcs differ (at least one share should be different)
		require.Equal(t, len(dealerFunc1), len(dealerFunc2))
		foundDifference := false
		for id := range dealerFunc1 {
			if !dealerFunc1[id].Equal(dealerFunc2[id]) {
				foundDifference = true
				break
			}
		}
		require.True(t, foundDifference, "dealer funcs should differ")

		// Verify reconstruction works for both
		reconstructed1, err3 := scheme.Reconstruct(out1.Shares().Values()...)
		require.NoError(t, err3)
		require.True(t, secret1.Equal(reconstructed1))
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		out, secret, dealerFunc, err := scheme.DealRandomAndRevealDealerFunc(nil)
		require.Error(t, err)
		require.Nil(t, out)
		require.Nil(t, secret)
		require.Nil(t, dealerFunc)
	})
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

	scheme, err := dnf.NewFiniteScheme(group, ac)
	require.NoError(t, err)

	secret := isn.NewSecret(group.FromUint64(999))
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	// Verify reconstruction with first minimal qualified set
	sharesMap := make(map[sharing.ID]*dnf.Share[*bls12381.Scalar])
	for id, share := range out.Shares().Iter() {
		sharesMap[id] = share
	}

	shares := []*dnf.Share[*bls12381.Scalar]{
		sharesMap[1],
		sharesMap[2],
		sharesMap[3],
	}
	reconstructed, err := scheme.Reconstruct(shares...)
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed))
}
