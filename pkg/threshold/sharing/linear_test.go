package sharing_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

func TestDNFAccessStructure_Creation(t *testing.T) {
	t.Parallel()

	t.Run("valid creation", func(t *testing.T) {
		t.Parallel()
		minimalSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](3, 4, 5).Freeze(),
		}
		ac, err := sharing.NewDNFAccessStructure(minimalSets...)
		require.NoError(t, err)
		require.NotNil(t, ac)
		require.Len(t, ac, 2)
	})

	t.Run("single minimal set", func(t *testing.T) {
		t.Parallel()
		minimalSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2, 3).Freeze(),
		}
		ac, err := sharing.NewDNFAccessStructure(minimalSets...)
		require.NoError(t, err)
		require.NotNil(t, ac)
		require.Len(t, ac, 1)
	})

	t.Run("nil sets", func(t *testing.T) {
		t.Parallel()
		ac, err := sharing.NewDNFAccessStructure(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
		require.Nil(t, ac)
	})

	t.Run("empty sets slice", func(t *testing.T) {
		t.Parallel()
		ac, err := sharing.NewDNFAccessStructure()
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, ac)
	})

	// Note: nil set in slice would panic during validation due to nil pointer access
	// This is an implementation issue where sj could be nil when calling si.Equal(sj)

	t.Run("empty set in slice", func(t *testing.T) {
		t.Parallel()
		minimalSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID]().Freeze(),
		}
		ac, err := sharing.NewDNFAccessStructure(minimalSets...)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, ac)
	})

	t.Run("duplicate sets", func(t *testing.T) {
		t.Parallel()
		minimalSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		}
		ac, err := sharing.NewDNFAccessStructure(minimalSets...)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, ac)
	})

	t.Run("subset violation", func(t *testing.T) {
		t.Parallel()
		// {1,2} is a subset of {1,2,3}, so not minimal
		minimalSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](1, 2, 3).Freeze(),
		}
		ac, err := sharing.NewDNFAccessStructure(minimalSets...)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, ac)
	})
}

func TestDNFAccessStructure_Shareholders(t *testing.T) {
	t.Parallel()

	t.Run("collect all shareholders", func(t *testing.T) {
		t.Parallel()
		minimalSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](3, 4).Freeze(),
		}
		ac, err := sharing.NewDNFAccessStructure(minimalSets...)
		require.NoError(t, err)

		shareholders := ac.Shareholders()
		require.Equal(t, 4, shareholders.Size())
		require.True(t, shareholders.Contains(1))
		require.True(t, shareholders.Contains(2))
		require.True(t, shareholders.Contains(3))
		require.True(t, shareholders.Contains(4))
	})

	t.Run("overlapping sets", func(t *testing.T) {
		t.Parallel()
		minimalSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](2, 3, 4).Freeze(),
		}
		ac, err := sharing.NewDNFAccessStructure(minimalSets...)
		require.NoError(t, err)

		shareholders := ac.Shareholders()
		require.Equal(t, 4, shareholders.Size())
		require.True(t, shareholders.Contains(1))
		require.True(t, shareholders.Contains(2))
		require.True(t, shareholders.Contains(3))
		require.True(t, shareholders.Contains(4))
	})
}

func TestDNFAccessStructure_IsAuthorized(t *testing.T) {
	t.Parallel()

	// Access structure: {1,2} OR {3,4,5}
	minimalSets := []ds.Set[sharing.ID]{
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4, 5).Freeze(),
	}
	ac, err := sharing.NewDNFAccessStructure(minimalSets...)
	require.NoError(t, err)

	tests := []struct {
		name       string
		ids        []sharing.ID
		authorized bool
	}{
		{"first minimal set", []sharing.ID{1, 2}, true},
		{"second minimal set", []sharing.ID{3, 4, 5}, true},
		{"superset of first", []sharing.ID{1, 2, 3}, true},
		{"superset of second", []sharing.ID{3, 4, 5, 6}, true},
		{"all parties", []sharing.ID{1, 2, 3, 4, 5}, true},
		{"single party", []sharing.ID{1}, false},
		{"subset of minimal", []sharing.ID{3, 4}, false},
		{"disjoint sets", []sharing.ID{1, 3}, false},
		{"empty set", []sharing.ID{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ac.IsAuthorized(tt.ids...)
			require.Equal(t, tt.authorized, result)
		})
	}
}

func TestDNFAccessStructure_CBOR(t *testing.T) {
	t.Parallel()

	t.Run("marshal and unmarshal", func(t *testing.T) {
		t.Parallel()
		minimalSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](3, 4, 5).Freeze(),
		}
		ac, err := sharing.NewDNFAccessStructure(minimalSets...)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(ac)
		require.NoError(t, err)
		require.NotNil(t, data)

		decoded, err := serde.UnmarshalCBOR[sharing.DNFAccessStructure](data)
		require.NoError(t, err)

		// Verify same number of sets
		require.Len(t, decoded, len(ac))

		// Verify same shareholders
		require.True(t, ac.Shareholders().Equal(decoded.Shareholders()))

		// Verify authorization works the same
		testCases := [][]sharing.ID{
			{1, 2},
			{3, 4, 5},
			{1, 3},
			{3, 4},
		}
		for _, ids := range testCases {
			require.Equal(t, ac.IsAuthorized(ids...), decoded.IsAuthorized(ids...))
		}
	})
}

func TestCNFAccessStructure_Creation(t *testing.T) {
	t.Parallel()

	t.Run("valid creation", func(t *testing.T) {
		t.Parallel()
		maximalUnqualifiedSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](3, 4).Freeze(),
		}
		ac, err := sharing.NewCNFAccessStructure(maximalUnqualifiedSets...)
		require.NoError(t, err)
		require.NotNil(t, ac)
		require.Len(t, ac, 2)
	})

	t.Run("single maximal unqualified set", func(t *testing.T) {
		t.Parallel()
		maximalUnqualifiedSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2, 3).Freeze(),
		}
		ac, err := sharing.NewCNFAccessStructure(maximalUnqualifiedSets...)
		require.NoError(t, err)
		require.NotNil(t, ac)
		require.Len(t, ac, 1)
	})

	t.Run("nil argument", func(t *testing.T) {
		t.Parallel()
		ac, err := sharing.NewCNFAccessStructure(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
		require.Nil(t, ac)
	})

	t.Run("empty sets slice", func(t *testing.T) {
		t.Parallel()
		ac, err := sharing.NewCNFAccessStructure()
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, ac)
	})

	t.Run("duplicate sets", func(t *testing.T) {
		t.Parallel()
		maximalUnqualifiedSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		}
		ac, err := sharing.NewCNFAccessStructure(maximalUnqualifiedSets...)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, ac)
	})

	t.Run("subset violation", func(t *testing.T) {
		t.Parallel()
		// {1,2} is a subset of {1,2,3}, so not maximal
		maximalUnqualifiedSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](1, 2, 3).Freeze(),
		}
		ac, err := sharing.NewCNFAccessStructure(maximalUnqualifiedSets...)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, ac)
	})
}

func TestCNFAccessStructure_Shareholders(t *testing.T) {
	t.Parallel()

	t.Run("collect all shareholders", func(t *testing.T) {
		t.Parallel()
		maximalUnqualifiedSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](3, 4).Freeze(),
		}
		ac, err := sharing.NewCNFAccessStructure(maximalUnqualifiedSets...)
		require.NoError(t, err)

		shareholders := ac.Shareholders()
		require.Equal(t, 4, shareholders.Size())
		require.True(t, shareholders.Contains(1))
		require.True(t, shareholders.Contains(2))
		require.True(t, shareholders.Contains(3))
		require.True(t, shareholders.Contains(4))
	})

	t.Run("overlapping sets", func(t *testing.T) {
		t.Parallel()
		maximalUnqualifiedSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2, 3).Freeze(),
			hashset.NewComparable[sharing.ID](2, 3, 4).Freeze(),
		}
		ac, err := sharing.NewCNFAccessStructure(maximalUnqualifiedSets...)
		require.NoError(t, err)

		shareholders := ac.Shareholders()
		require.Equal(t, 4, shareholders.Size())
		require.True(t, shareholders.Contains(1))
		require.True(t, shareholders.Contains(2))
		require.True(t, shareholders.Contains(3))
		require.True(t, shareholders.Contains(4))
	})
}

func TestCNFAccessStructure_IsAuthorized(t *testing.T) {
	t.Parallel()

	// Maximal unqualified sets: {1,2} and {3,4}
	// Authorized: must have at least one from NOT{1,2} AND at least one from NOT{3,4}
	maximalUnqualifiedSets := []ds.Set[sharing.ID]{
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4).Freeze(),
	}
	ac, err := sharing.NewCNFAccessStructure(maximalUnqualifiedSets...)
	require.NoError(t, err)

	tests := []struct {
		name       string
		ids        []sharing.ID
		authorized bool
	}{
		{"authorized {1,3}", []sharing.ID{1, 3}, true},
		{"authorized {1,4}", []sharing.ID{1, 4}, true},
		{"authorized {2,3}", []sharing.ID{2, 3}, true},
		{"authorized {2,4}", []sharing.ID{2, 4}, true},
		{"authorized {1,2,3}", []sharing.ID{1, 2, 3}, true},
		{"authorized {1,2,4}", []sharing.ID{1, 2, 4}, true},
		{"authorized all", []sharing.ID{1, 2, 3, 4}, true},
		{"unauthorised {1,2}", []sharing.ID{1, 2}, false},
		{"unauthorised {3,4}", []sharing.ID{3, 4}, false},
		{"unauthorised {1}", []sharing.ID{1}, false},
		{"unauthorised empty", []sharing.ID{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ac.IsAuthorized(tt.ids...)
			require.Equal(t, tt.authorized, result)
		})
	}
}

func TestCNFAccessStructure_CBOR(t *testing.T) {
	t.Parallel()

	t.Run("marshal and unmarshal", func(t *testing.T) {
		t.Parallel()
		maximalUnqualifiedSets := []ds.Set[sharing.ID]{
			hashset.NewComparable[sharing.ID](1, 2).Freeze(),
			hashset.NewComparable[sharing.ID](3, 4, 5).Freeze(),
		}
		ac, err := sharing.NewCNFAccessStructure(maximalUnqualifiedSets...)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(ac)
		require.NoError(t, err)
		require.NotNil(t, data)

		decoded, err := serde.UnmarshalCBOR[sharing.CNFAccessStructure](data)
		require.NoError(t, err)

		// Verify same number of sets
		require.Len(t, decoded, len(ac))

		// Verify same shareholders
		require.True(t, ac.Shareholders().Equal(decoded.Shareholders()))

		// Verify authorization works the same
		testCases := [][]sharing.ID{
			{1, 3},
			{1, 2},
			{3, 4, 5},
			{1, 2, 3},
		}
		for _, ids := range testCases {
			require.Equal(t, ac.IsAuthorized(ids...), decoded.IsAuthorized(ids...))
		}
	})
}

func TestUnanimityAccessStructure_Creation(t *testing.T) {
	t.Parallel()

	t.Run("valid creation", func(t *testing.T) {
		t.Parallel()
		shareholders := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
		ac, err := sharing.NewUnanimityAccessStructure(shareholders)
		require.NoError(t, err)
		require.NotNil(t, ac)
	})

	t.Run("minimum two shareholders", func(t *testing.T) {
		t.Parallel()
		shareholders := hashset.NewComparable[sharing.ID](1, 2).Freeze()
		ac, err := sharing.NewUnanimityAccessStructure(shareholders)
		require.NoError(t, err)
		require.NotNil(t, ac)
	})

	t.Run("nil shareholders", func(t *testing.T) {
		t.Parallel()
		ac, err := sharing.NewUnanimityAccessStructure(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
		require.Nil(t, ac)
	})

	t.Run("single shareholder", func(t *testing.T) {
		t.Parallel()
		shareholders := hashset.NewComparable[sharing.ID](1).Freeze()
		ac, err := sharing.NewUnanimityAccessStructure(shareholders)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, ac)
	})

	t.Run("empty shareholders", func(t *testing.T) {
		t.Parallel()
		shareholders := hashset.NewComparable[sharing.ID]().Freeze()
		ac, err := sharing.NewUnanimityAccessStructure(shareholders)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, ac)
	})
}

func TestUnanimityAccessStructure_Shareholders(t *testing.T) {
	t.Parallel()

	shareholders := hashset.NewComparable[sharing.ID](1, 2, 3, 4).Freeze()
	ac, err := sharing.NewUnanimityAccessStructure(shareholders)
	require.NoError(t, err)

	result := ac.Shareholders()
	require.Equal(t, 4, result.Size())
	require.True(t, result.Equal(shareholders))
}

func TestUnanimityAccessStructure_IsAuthorized(t *testing.T) {
	t.Parallel()

	shareholders := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
	ac, err := sharing.NewUnanimityAccessStructure(shareholders)
	require.NoError(t, err)

	tests := []struct {
		name       string
		ids        []sharing.ID
		authorized bool
	}{
		{"all shareholders", []sharing.ID{1, 2, 3}, true},
		{"all shareholders different order", []sharing.ID{3, 1, 2}, true},
		{"subset", []sharing.ID{1, 2}, false},
		{"superset", []sharing.ID{1, 2, 3, 4}, false},
		{"single party", []sharing.ID{1}, false},
		{"empty", []sharing.ID{}, false},
		{"wrong parties", []sharing.ID{4, 5, 6}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ac.IsAuthorized(tt.ids...)
			require.Equal(t, tt.authorized, result)
		})
	}
}

func TestUnanimityAccessStructure_CBOR(t *testing.T) {
	t.Parallel()

	t.Run("marshal and unmarshal", func(t *testing.T) {
		t.Parallel()
		shareholders := hashset.NewComparable[sharing.ID](1, 2, 3, 4, 5).Freeze()
		ac, err := sharing.NewUnanimityAccessStructure(shareholders)
		require.NoError(t, err)

		data, err := ac.MarshalCBOR()
		require.NoError(t, err)
		require.NotNil(t, data)

		var decoded sharing.UnanimityAccessStructure
		err = decoded.UnmarshalCBOR(data)
		require.NoError(t, err)

		// Verify same shareholders
		require.True(t, ac.Shareholders().Equal(decoded.Shareholders()))

		// Verify authorization works the same
		testCases := [][]sharing.ID{
			{1, 2, 3, 4, 5},
			{1, 2, 3},
			{1, 2, 3, 4, 5, 6},
		}
		for _, ids := range testCases {
			require.Equal(t, ac.IsAuthorized(ids...), decoded.IsAuthorized(ids...))
		}
	})
}
