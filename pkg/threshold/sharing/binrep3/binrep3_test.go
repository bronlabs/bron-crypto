package binrep3

import (
	crand "crypto/rand"
	"math/bits"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/stretchr/testify/require"
)

const THRESHOLD = 2
const TOTAL = 3

func Test_RoundTrip(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	shareholders := sharing.NewOrdinalShareholderSet(3)
	scheme, err := NewScheme(shareholders)
	require.NoError(t, err)

	secret, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)
	dealerOutput, err := scheme.Deal(secret, prng)
	require.NoError(t, err)
	shares := dealerOutput.Shares().Values()
	require.Len(t, shares, TOTAL)

	t.Run("should reconstruct secret", func(t *testing.T) {
		t.Parallel()
		for subShares := range sliceutils.KCoveringCombinations(shares, THRESHOLD) {
			reconstructed, err := scheme.Reconstruct(subShares...)
			require.NoError(t, err)
			require.Equal(t, secret, reconstructed)
		}
	})
}

func Test_HomomorphicXor(t *testing.T) {
	prng := crand.Reader
	shareholders := sharing.NewOrdinalShareholderSet(3)
	scheme, err := NewScheme(shareholders)
	require.NoError(t, err)

	secret1, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)
	dealerOutput1, err := scheme.Deal(secret1, prng)
	require.NoError(t, err)

	secret2, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)
	dealerOutput2, err := scheme.Deal(secret2, prng)
	require.NoError(t, err)

	secret3 := secret1 ^ secret2
	var shares3 []*Share
	for id := range shareholders.Iter() {
		l, _ := dealerOutput1.Shares().Get(id)
		r, _ := dealerOutput2.Shares().Get(id)
		shares3 = append(shares3, l.Xor(r))
	}

	t.Run("should reconstruct secret", func(t *testing.T) {
		t.Parallel()
		for subShares := range sliceutils.KCoveringCombinations(shares3, THRESHOLD) {
			reconstructed, err := scheme.Reconstruct(subShares...)
			require.NoError(t, err)
			require.Equal(t, secret3, reconstructed)
		}
	})
}

func Test_HomomorphicXorPublic(t *testing.T) {
	prng := crand.Reader
	shareholders := sharing.NewOrdinalShareholderSet(3)
	scheme, err := NewScheme(shareholders)
	require.NoError(t, err)

	secret1, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)
	dealerOutput1, err := scheme.Deal(secret1, prng)
	require.NoError(t, err)

	public2, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)

	secret3 := secret1 ^ public2
	var shares3 []*Share
	for id := range shareholders.Iter() {
		l, _ := dealerOutput1.Shares().Get(id)
		shares3 = append(shares3, l.XorPublic(public2))
	}

	t.Run("should reconstruct secret", func(t *testing.T) {
		t.Parallel()
		for subShares := range sliceutils.KCoveringCombinations(shares3, THRESHOLD) {
			reconstructed, err := scheme.Reconstruct(subShares...)
			require.NoError(t, err)
			require.Equal(t, secret3, reconstructed)
		}
	})
}

func Test_HomomorphicAndPublic(t *testing.T) {
	prng := crand.Reader
	shareholders := sharing.NewOrdinalShareholderSet(3)
	scheme, err := NewScheme(shareholders)
	require.NoError(t, err)

	secret1, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)
	dealerOutput1, err := scheme.Deal(secret1, prng)
	require.NoError(t, err)

	public2, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)

	secret3 := secret1 & public2
	var shares3 []*Share
	for id := range shareholders.Iter() {
		l, _ := dealerOutput1.Shares().Get(id)
		shares3 = append(shares3, l.AndPublic(public2))
	}

	t.Run("should reconstruct secret", func(t *testing.T) {
		t.Parallel()
		for subShares := range sliceutils.KCoveringCombinations(shares3, THRESHOLD) {
			reconstructed, err := scheme.Reconstruct(subShares...)
			require.NoError(t, err)
			require.Equal(t, secret3, reconstructed)
		}
	})
}

func Test_PseudoHomomorphicShiftLeft(t *testing.T) {
	prng := crand.Reader
	shareholders := sharing.NewOrdinalShareholderSet(3)
	scheme, err := NewScheme(shareholders)
	require.NoError(t, err)

	secret1, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)
	dealerOutput1, err := scheme.Deal(secret1, prng)
	require.NoError(t, err)

	k, err := mathutils.RandomUint64Range(prng, 64)
	require.NoError(t, err)

	secret3 := secret1 << k
	var shares3 []*Share
	for id := range shareholders.Iter() {
		l, _ := dealerOutput1.Shares().Get(id)
		shares3 = append(shares3, l.ShiftLeft(int(k)))
	}

	t.Run("should reconstruct secret", func(t *testing.T) {
		t.Parallel()
		for subShares := range sliceutils.KCoveringCombinations(shares3, THRESHOLD) {
			reconstructed, err := scheme.Reconstruct(subShares...)
			require.NoError(t, err)
			require.Equal(t, secret3, reconstructed)
		}
	})
}

func Test_PseudoHomomorphicShiftRight(t *testing.T) {
	prng := crand.Reader
	shareholders := sharing.NewOrdinalShareholderSet(3)
	scheme, err := NewScheme(shareholders)
	require.NoError(t, err)

	secret1, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)
	dealerOutput1, err := scheme.Deal(secret1, prng)
	require.NoError(t, err)

	k, err := mathutils.RandomUint64Range(prng, 64)
	require.NoError(t, err)

	secret3 := secret1 >> k
	var shares3 []*Share
	for id := range shareholders.Iter() {
		l, _ := dealerOutput1.Shares().Get(id)
		shares3 = append(shares3, l.ShiftRight(int(k)))
	}

	t.Run("should reconstruct secret", func(t *testing.T) {
		t.Parallel()
		for subShares := range sliceutils.KCoveringCombinations(shares3, THRESHOLD) {
			reconstructed, err := scheme.Reconstruct(subShares...)
			require.NoError(t, err)
			require.Equal(t, secret3, reconstructed)
		}
	})
}

func Test_PseudoHomomorphicRotateRight(t *testing.T) {
	prng := crand.Reader
	shareholders := sharing.NewOrdinalShareholderSet(3)
	scheme, err := NewScheme(shareholders)
	require.NoError(t, err)

	secret1, err := mathutils.RandomUint64(prng)
	require.NoError(t, err)
	dealerOutput1, err := scheme.Deal(secret1, prng)
	require.NoError(t, err)

	k, err := mathutils.RandomUint64Range(prng, 64)
	require.NoError(t, err)

	secret3 := bits.RotateLeft64(secret1, -int(k))
	var shares3 []*Share
	for id := range shareholders.Iter() {
		l, _ := dealerOutput1.Shares().Get(id)
		shares3 = append(shares3, l.RotateRight(int(k)))
	}

	t.Run("should reconstruct secret", func(t *testing.T) {
		t.Parallel()
		for subShares := range sliceutils.KCoveringCombinations(shares3, THRESHOLD) {
			reconstructed, err := scheme.Reconstruct(subShares...)
			require.NoError(t, err)
			require.Equal(t, secret3, reconstructed)
		}
	})
}
