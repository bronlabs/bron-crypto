//nolint:testpackage // White-box tests validate internal access-structure state.
package accessstructures

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

func TestNewThreshold(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		ps := hashset.NewComparable[ID](1, 2, 3, 4).Freeze()

		a, err := NewThresholdAccessStructure(3, ps)
		require.NoError(t, err)
		require.NotNil(t, a)
		require.Equal(t, uint(3), a.Threshold())
		require.True(t, a.Shareholders().Equal(ps))
	})

	t.Run("nil shareholders", func(t *testing.T) {
		t.Parallel()

		a, err := NewThresholdAccessStructure(2, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrIsNil)
		require.Nil(t, a)
	})

	t.Run("shareholders contains zero", func(t *testing.T) {
		t.Parallel()

		a, err := NewThresholdAccessStructure(2, hashset.NewComparable[ID](0, 1, 2).Freeze())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMembership)
		require.Nil(t, a)
	})

	t.Run("threshold less than 2", func(t *testing.T) {
		t.Parallel()

		a, err := NewThresholdAccessStructure(1, hashset.NewComparable[ID](1, 2).Freeze())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, a)
	})

	t.Run("threshold greater than shareholder count", func(t *testing.T) {
		t.Parallel()

		a, err := NewThresholdAccessStructure(4, hashset.NewComparable[ID](1, 2, 3).Freeze())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, a)
	})
}

func TestThresholdIsQualified(t *testing.T) {
	t.Parallel()

	a, err := NewThresholdAccessStructure(3, hashset.NewComparable[ID](1, 2, 3, 4).Freeze())
	require.NoError(t, err)

	tests := []struct {
		name      string
		ids       []ID
		qualified bool
	}{
		{name: "exactly threshold", ids: []ID{1, 2, 3}, qualified: true},
		{name: "all shareholders", ids: []ID{1, 2, 3, 4}, qualified: true},
		{name: "duplicates still qualify", ids: []ID{1, 1, 2, 3}, qualified: true},
		{name: "below threshold", ids: []ID{1, 2}, qualified: false},
		{name: "contains outsider", ids: []ID{1, 2, 99}, qualified: false},
		{name: "empty", ids: []ID{}, qualified: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.qualified, a.IsQualified(tc.ids...))
		})
	}
}

func TestThresholdMaxUnqualifiedSetsIter(t *testing.T) {
	t.Parallel()

	a, err := NewThresholdAccessStructure(3, hashset.NewComparable[ID](1, 2, 3, 4).Freeze())
	require.NoError(t, err)

	got := make(map[string]struct{})
	for subset := range a.MaximalUnqualifiedSetsIter() {
		require.Equal(t, 2, subset.Size())
		require.False(t, a.IsQualified(subset.List()...))
		got[canonicalIDs(subset)] = struct{}{}
	}

	expected := map[string]struct{}{
		"1,2": {},
		"1,3": {},
		"1,4": {},
		"2,3": {},
		"2,4": {},
		"3,4": {},
	}
	require.Equal(t, expected, got)

	t.Run("iterator can stop early", func(t *testing.T) {
		t.Parallel()

		count := 0
		for range a.MaximalUnqualifiedSetsIter() {
			count++
			break
		}
		require.Equal(t, 1, count)
	})
}

func TestThresholdEqual(t *testing.T) {
	t.Parallel()

	ps123 := hashset.NewComparable[ID](1, 2, 3).Freeze()
	ps124 := hashset.NewComparable[ID](1, 2, 4).Freeze()

	a, err := NewThresholdAccessStructure(2, ps123)
	require.NoError(t, err)
	b, err := NewThresholdAccessStructure(2, hashset.NewComparable[ID](1, 2, 3).Freeze())
	require.NoError(t, err)
	c, err := NewThresholdAccessStructure(3, ps123)
	require.NoError(t, err)
	d, err := NewThresholdAccessStructure(2, ps124)
	require.NoError(t, err)

	require.True(t, a.Equal(b))
	require.False(t, a.Equal(c))
	require.False(t, a.Equal(d))

	var nilA *Threshold
	require.True(t, nilA.Equal(nil))
	require.False(t, nilA.Equal(a))
	require.False(t, a.Equal(nilA))
}

func TestThresholdClone(t *testing.T) {
	t.Parallel()

	a, err := NewThresholdAccessStructure(2, hashset.NewComparable[ID](1, 2, 3).Freeze())
	require.NoError(t, err)

	clone := a.Clone()
	require.NotNil(t, clone)
	require.NotSame(t, a, clone)
	require.True(t, a.Equal(clone))
	require.NotSame(t, a.Shareholders(), clone.Shareholders())

	var nilA *Threshold
	require.Nil(t, nilA.Clone())
}

func TestThresholdCBORRoundTrip(t *testing.T) {
	t.Parallel()

	original, err := NewThresholdAccessStructure(2, hashset.NewComparable[ID](10, 20, 30).Freeze())
	require.NoError(t, err)

	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[Threshold](data)
	require.NoError(t, err)
	require.True(t, original.Equal(&decoded))

	cases := [][]ID{{10, 20}, {10, 20, 30}, {10}, {10, 99}}
	for _, ids := range cases {
		require.Equal(t, original.IsQualified(ids...), decoded.IsQualified(ids...))
	}
}

func TestThresholdUnmarshalCBOR(t *testing.T) {
	t.Parallel()

	t.Run("invalid bytes", func(t *testing.T) {
		t.Parallel()

		var a Threshold
		err := a.UnmarshalCBOR([]byte{0xff, 0x00, 0x01})
		require.Error(t, err)
		require.ErrorIs(t, err, serde.ErrDeserialisation)
	})

	t.Run("decoded payload fails validation", func(t *testing.T) {
		t.Parallel()

		data, err := serde.MarshalCBOR(&thresholdDTO{
			T:  3,
			Ps: map[ID]bool{1: true, 2: true},
		})
		require.NoError(t, err)

		var a Threshold
		err = a.UnmarshalCBOR(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
	})
}
