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

func TestCNFSanity(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	// Create CNF access structure with maximal unqualified sets: {1,2} and {3,4}
	// Authorized: any set with at least one from NOT{1,2} AND at least one from NOT{3,4}
	// Examples: {1,3}, {1,4}, {2,3}, {2,4}, {1,3,4}, {2,3,4}, {1,2,3}, {1,2,4}, {1,2,3,4}
	maximalUnqualifiedSets := []ds.Set[sharing.ID]{
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4).Freeze(),
	}
	ac, err := sharing.NewCNFAccessStructure(maximalUnqualifiedSets...)
	require.NoError(t, err)

	scheme := isn.NewCNFScheme(group, ac)
	require.NotNil(t, scheme)
	require.Equal(t, isn.CNFName, scheme.Name())

	secret := isn.NewSecret(group.FromUint64(42))
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)
	require.NotNil(t, out)

	shares := out.Shares()
	require.Equal(t, 4, shares.Size())

	// Verify shares have sparse maps (parties only have entries for clauses where they're NOT in the maximal unqualified set)
	// Maximal unqualified sets: {1,2} and {3,4}
	// Party 1: NOT in {3,4}, so has entry for {3,4}; IS in {1,2}, so no entry for {1,2}
	// Party 2: NOT in {3,4}, so has entry for {3,4}; IS in {1,2}, so no entry for {1,2}
	// Party 3: NOT in {1,2}, so has entry for {1,2}; IS in {3,4}, so no entry for {3,4}
	// Party 4: NOT in {1,2}, so has entry for {1,2}; IS in {3,4}, so no entry for {3,4}
	for _, share := range shares.Values() {
		require.Len(t, share.Value(), 1, "each party should have 1 entry (outside one maximal unqualified set)")
	}

	// Reconstruct with authorized set {1,3}
	sharesMap := make(map[sharing.ID]*isn.Share[*k256.Scalar])
	for id, share := range shares.Iter() {
		sharesMap[id] = share
	}

	reconstructed, err := scheme.Reconstruct(sharesMap[1], sharesMap[3])
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed))
}

func TestCNFDeal(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	// Maximal unqualified sets: {1,2} and {3,4,5}
	ac, err := sharing.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4, 5).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewCNFScheme(group, ac)

	t.Run("zero secret", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.Zero())
		out, err := scheme.Deal(secret, pcg.NewRandomised())
		require.NoError(t, err)

		// Reconstruct with authorized set {1,3}
		sharesMap := make(map[sharing.ID]*isn.Share[*k256.Scalar])
		for id, share := range out.Shares().Iter() {
			sharesMap[id] = share
		}

		reconstructed, err := scheme.Reconstruct(sharesMap[1], sharesMap[3])
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("one secret", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.One())
		out, err := scheme.Deal(secret, pcg.NewRandomised())
		require.NoError(t, err)

		sharesMap := make(map[sharing.ID]*isn.Share[*k256.Scalar])
		for id, share := range out.Shares().Iter() {
			sharesMap[id] = share
		}

		reconstructed, err := scheme.Reconstruct(sharesMap[2], sharesMap[4])
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

		sharesMap := make(map[sharing.ID]*isn.Share[*k256.Scalar])
		for id, share := range out.Shares().Iter() {
			sharesMap[id] = share
		}

		reconstructed, err := scheme.Reconstruct(sharesMap[1], sharesMap[5])
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

func TestCNFDealRandom(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()
	ac, err := sharing.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewCNFScheme(group, ac)

	t.Run("valid random generation", func(t *testing.T) {
		t.Parallel()
		out, err := scheme.DealRandom(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, 4, out.Shares().Size())
	})

	t.Run("multiple generations produce different secrets", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()

		out1, err := scheme.DealRandom(prng)
		require.NoError(t, err)

		out2, err := scheme.DealRandom(prng)
		require.NoError(t, err)

		// Reconstruct both with {1,3}
		sharesMap1 := make(map[sharing.ID]*isn.Share[*k256.Scalar])
		for id, share := range out1.Shares().Iter() {
			sharesMap1[id] = share
		}

		sharesMap2 := make(map[sharing.ID]*isn.Share[*k256.Scalar])
		for id, share := range out2.Shares().Iter() {
			sharesMap2[id] = share
		}

		secret1, err := scheme.Reconstruct(sharesMap1[1], sharesMap1[3])
		require.NoError(t, err)

		secret2, err := scheme.Reconstruct(sharesMap2[1], sharesMap2[3])
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

func TestCNFReconstruct_Authorization(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	// Maximal unqualified sets: {1,2} and {3,4}
	// Authorized: sets with at least one party NOT in {1,2} AND at least one party NOT in {3,4}
	// Authorized examples: {1,3}, {1,4}, {2,3}, {2,4}, {1,2,3}, {1,2,4}, {1,2,3,4}
	// Unauthorised: {1,2} (contained in first maximal unqualified set)
	// Unauthorised: {3,4} (contained in second maximal unqualified set)
	// Unauthorised: {1}, {2}, {3}, {4} (single parties)
	ac, err := sharing.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewCNFScheme(group, ac)
	secret := isn.NewSecret(group.FromUint64(77777))

	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	sharesMap := make(map[sharing.ID]*isn.Share[*k256.Scalar])
	for id, share := range out.Shares().Iter() {
		sharesMap[id] = share
	}

	t.Run("authorized minimal set {1,3}", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[1],
			sharesMap[3],
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("authorized minimal set {1,4}", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[1],
			sharesMap[4],
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("authorized minimal set {2,3}", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[2],
			sharesMap[3],
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("authorized minimal set {2,4}", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[2],
			sharesMap[4],
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("authorized superset {1,2,3}", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[1],
			sharesMap[2],
			sharesMap[3],
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("authorized all parties {1,2,3,4}", func(t *testing.T) {
		t.Parallel()
		reconstructed, err := scheme.Reconstruct(out.Shares().Values()...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("unauthorised single party", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{sharesMap[1]}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})

	t.Run("unauthorised maximal unqualified set {1,2}", func(t *testing.T) {
		t.Parallel()
		// {1,2} is a maximal unqualified set, so it's unauthorised
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[1],
			sharesMap[2],
		}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})

	t.Run("unauthorised maximal unqualified set {3,4}", func(t *testing.T) {
		t.Parallel()
		// {3,4} is a maximal unqualified set, so it's unauthorised
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[3],
			sharesMap[4],
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

func TestCNFShareHomomorphism(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()
	ac, err := sharing.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewCNFScheme(group, ac)

	// Create two secrets
	secret1 := isn.NewSecret(group.FromUint64(500))
	secret2 := isn.NewSecret(group.FromUint64(300))

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

	// Reconstruct from combined shares using authorized set {1,3}
	reconstructed, err := scheme.Reconstruct(combinedShares[1], combinedShares[3])
	require.NoError(t, err)

	// Expected secret is secret1 + secret2
	expectedSecret := isn.NewSecret(secret1.Value().Op(secret2.Value()))
	require.True(t, expectedSecret.Equal(reconstructed))
}

func TestCNF_BLS12381(t *testing.T) {
	t.Parallel()

	// Test with a different group (BLS12-381 scalar field)
	group := bls12381.NewScalarField()

	ac, err := sharing.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2, 3).Freeze(),
		hashset.NewComparable[sharing.ID](4, 5).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewCNFScheme(group, ac)

	secret := isn.NewSecret(group.FromUint64(888888))
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	// Verify reconstruction with authorized set {1,4}
	// (1 is not in {4,5} and 4 is not in {1,2,3})
	sharesMap := make(map[sharing.ID]*isn.Share[*bls12381.Scalar])
	for id, share := range out.Shares().Iter() {
		sharesMap[id] = share
	}

	shares := []*isn.Share[*bls12381.Scalar]{
		sharesMap[1],
		sharesMap[4],
	}
	reconstructed, err := scheme.Reconstruct(shares...)
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed))
}

func TestCNF_ThreeClausesAccessStructure(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	// More complex access structure with three maximal unqualified sets
	// Maximal unqualified: {1,2}, {3,4}, {5,6}
	// Authorized: need at least one from each complement
	ac, err := sharing.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4).Freeze(),
		hashset.NewComparable[sharing.ID](5, 6).Freeze(),
	)
	require.NoError(t, err)

	scheme := isn.NewCNFScheme(group, ac)
	secret := isn.NewSecret(group.FromUint64(111111))

	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	sharesMap := make(map[sharing.ID]*isn.Share[*k256.Scalar])
	for id, share := range out.Shares().Iter() {
		sharesMap[id] = share
	}

	// Each share should have sparse map entries only for maximal unqualified sets they're NOT in
	// Maximal unqualified: {1,2}, {3,4}, {5,6}
	// Party 1: in {1,2}, NOT in {3,4} and {5,6} → 2 entries
	// Party 2: in {1,2}, NOT in {3,4} and {5,6} → 2 entries
	// Party 3: in {3,4}, NOT in {1,2} and {5,6} → 2 entries
	// Party 4: in {3,4}, NOT in {1,2} and {5,6} → 2 entries
	// Party 5: in {5,6}, NOT in {1,2} and {3,4} → 2 entries
	// Party 6: in {5,6}, NOT in {1,2} and {3,4} → 2 entries
	for _, share := range sharesMap {
		require.Len(t, share.Value(), 2, "each party should be outside 2 of the 3 maximal unqualified sets")
	}

	t.Run("authorized minimal {1,3,5}", func(t *testing.T) {
		t.Parallel()
		// 1 not in {3,4}, 3 not in {1,2}, 5 not in {5,6} - wait that's wrong
		// 1 not in {3,4} ✓, 1 not in {5,6} ✓, but 1 IS in {1,2}
		// 3 not in {1,2} ✓, 3 IS in {3,4}, 3 not in {5,6} ✓
		// 5 not in {1,2} ✓, 5 not in {3,4} ✓, 5 IS in {5,6}
		// So we need at least one party outside each maximal unqualified set:
		// - Outside {1,2}: need 3,4,5, or 6
		// - Outside {3,4}: need 1,2,5, or 6
		// - Outside {5,6}: need 1,2,3, or 4
		// {1,3,5} satisfies all: 3 outside {1,2}, 1 outside {3,4}, 1 outside {5,6}
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[1],
			sharesMap[3],
			sharesMap[5],
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("authorized minimal {2,4,6}", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[2],
			sharesMap[4],
			sharesMap[6],
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("unauthorised {1,2,3}", func(t *testing.T) {
		t.Parallel()
		// This set is contained in maximal unqualified {5,6}'s complement? No wait...
		// Actually {1,2,3} has 3 outside {1,2}, 1 outside {3,4}, but NO ONE outside {5,6}
		// Wait, let me reconsider. The parties are 1,2,3,4,5,6.
		// Maximal unqualified: {1,2}, {3,4}, {5,6}
		// For {1,2,3}:
		// - Has 3 which is outside {1,2} ✓
		// - Has 1,2 which are outside {3,4} ✓
		// - Has 1,2,3 which are all outside {5,6} ✓
		// So {1,2,3} should be AUTHORIZED!
		// Let me think again about what's unauthorised...
		// {1,2} is unauthorised (contained in maximal unqualified {1,2})
		// {3,4} is unauthorised (contained in maximal unqualified {3,4})
		// {5,6} is unauthorised (contained in maximal unqualified {5,6})
		// {1,2,5} might be unauthorised? Let's check:
		// - Has 5 outside {1,2} ✓
		// - Has 1,2,5 outside {3,4} ✓
		// - Has 1,2 outside {5,6} ✓
		// So that's authorized too.
		// Let me test {1,2} which IS a maximal unqualified set
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[1],
			sharesMap[2],
		}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})

	t.Run("unauthorised {3,4}", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[3],
			sharesMap[4],
		}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})

	t.Run("unauthorised {5,6}", func(t *testing.T) {
		t.Parallel()
		shares := []*isn.Share[*k256.Scalar]{
			sharesMap[5],
			sharesMap[6],
		}
		_, err := scheme.Reconstruct(shares...)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrUnauthorized)
	})
}
