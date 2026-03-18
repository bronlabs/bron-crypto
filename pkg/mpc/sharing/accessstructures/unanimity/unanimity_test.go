//nolint:testpackage // White-box tests validate internal access-structure state.
package unanimity

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func TestNewUnanimity(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		shareholders := hashset.NewComparable[ID](1, 2, 3).Freeze()

		u, err := NewUnanimityAccessStructure(shareholders)
		require.NoError(t, err)
		require.NotNil(t, u)
		require.True(t, u.Shareholders().Equal(shareholders))
	})

	t.Run("nil shareholders", func(t *testing.T) {
		t.Parallel()

		u, err := NewUnanimityAccessStructure(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrIsNil)
		require.Nil(t, u)
	})

	t.Run("too few shareholders", func(t *testing.T) {
		t.Parallel()

		u, err := NewUnanimityAccessStructure(hashset.NewComparable[ID](1).Freeze())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, u)
	})
}

func TestUnanimityIsQualified(t *testing.T) {
	t.Parallel()

	u, err := NewUnanimityAccessStructure(hashset.NewComparable[ID](1, 2, 3).Freeze())
	require.NoError(t, err)

	tests := []struct {
		name      string
		ids       []ID
		qualified bool
	}{
		{name: "exact set", ids: []ID{1, 2, 3}, qualified: true},
		{name: "superset including outsider", ids: []ID{1, 2, 3, 99}, qualified: false},
		{name: "duplicates still qualified", ids: []ID{1, 1, 2, 3}, qualified: true},
		{name: "missing shareholder", ids: []ID{1, 2}, qualified: false},
		{name: "outsider only", ids: []ID{99}, qualified: false},
		{name: "empty", ids: []ID{}, qualified: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.qualified, u.IsQualified(tc.ids...))
		})
	}
}

func TestUnanimityMaxUnqualifiedSetsIter(t *testing.T) {
	t.Parallel()

	shareholders := hashset.NewComparable[ID](1, 2, 3).Freeze()
	u, err := NewUnanimityAccessStructure(shareholders)
	require.NoError(t, err)

	got := make(map[string]struct{})
	for subset := range u.MaximalUnqualifiedSetsIter() {
		require.Equal(t, shareholders.Size()-1, subset.Size())
		require.True(t, subset.IsSubSet(shareholders))
		require.False(t, u.IsQualified(subset.List()...))
		got[canonicalIDs(subset)] = struct{}{}
	}

	expected := map[string]struct{}{
		"1,2": {},
		"1,3": {},
		"2,3": {},
	}
	require.Equal(t, expected, got)

	t.Run("iterator can stop early", func(t *testing.T) {
		t.Parallel()

		count := 0
		for range u.MaximalUnqualifiedSetsIter() {
			count++
			break
		}
		require.Equal(t, 1, count)
	})
}

func TestUnanimityEqual(t *testing.T) {
	t.Parallel()

	ps123 := hashset.NewComparable[ID](1, 2, 3).Freeze()
	ps124 := hashset.NewComparable[ID](1, 2, 4).Freeze()

	a, err := NewUnanimityAccessStructure(ps123)
	require.NoError(t, err)
	b, err := NewUnanimityAccessStructure(hashset.NewComparable[ID](1, 2, 3).Freeze())
	require.NoError(t, err)
	c, err := NewUnanimityAccessStructure(ps124)
	require.NoError(t, err)

	require.True(t, a.Equal(b))
	require.False(t, a.Equal(c))

	var nilA *Unanimity
	require.True(t, nilA.Equal(nil))
	require.False(t, nilA.Equal(a))
	require.False(t, a.Equal(nilA))
}

func TestUnanimityClone(t *testing.T) {
	t.Parallel()

	u, err := NewUnanimityAccessStructure(hashset.NewComparable[ID](1, 2, 3).Freeze())
	require.NoError(t, err)

	clone := u.Clone()
	require.NotNil(t, clone)
	require.NotSame(t, u, clone)
	require.True(t, u.Equal(clone))
	require.NotSame(t, u.Shareholders(), clone.Shareholders())

	var nilU *Unanimity
	require.Nil(t, nilU.Clone())
}

func TestUnanimityCBORRoundTrip(t *testing.T) {
	t.Parallel()

	original, err := NewUnanimityAccessStructure(hashset.NewComparable[ID](2, 4, 8, 16).Freeze())
	require.NoError(t, err)

	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[Unanimity](data)
	require.NoError(t, err)

	require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
	cases := [][]ID{{2, 4, 8, 16}, {2, 4, 8, 16, 99}, {2, 4, 8}}
	for _, ids := range cases {
		require.Equal(t, original.IsQualified(ids...), decoded.IsQualified(ids...))
	}
}

func TestUnanimityUnmarshalCBOR(t *testing.T) {
	t.Parallel()

	t.Run("invalid bytes", func(t *testing.T) {
		t.Parallel()

		var u Unanimity
		err := u.UnmarshalCBOR([]byte{0xff, 0x00, 0x01})
		require.Error(t, err)
	})

	t.Run("decoded payload fails validation", func(t *testing.T) {
		t.Parallel()

		data, err := serde.MarshalCBOR(unanimityDTO{Ps: map[ID]bool{1: true}})
		require.NoError(t, err)

		var u Unanimity
		err = u.UnmarshalCBOR(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
	})
}

func TestInducedByUnanimity_Errors(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	ac, err := NewUnanimityAccessStructure(hashset.NewComparable[ID](1, 2, 3).Freeze())
	require.NoError(t, err)

	t.Run("nil field", func(t *testing.T) {
		t.Parallel()
		m, err := InducedMSP[*k256.Scalar](nil, ac)
		require.ErrorIs(t, err, ErrIsNil)
		require.Nil(t, m)
	})

	t.Run("nil access structure", func(t *testing.T) {
		t.Parallel()
		m, err := InducedMSP(field, nil)
		require.ErrorIs(t, err, ErrIsNil)
		require.Nil(t, m)
	})
}

func TestInducedByUnanimity_AcceptsAndRejects(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	tests := []struct {
		name string
		ids  []ID
	}{
		{name: "3 shareholders", ids: []ID{1, 2, 3}},
		{name: "4 shareholders", ids: []ID{1, 2, 3, 4}},
		{name: "2 shareholders", ids: []ID{1, 2}},
		{name: "non-contiguous IDs", ids: []ID{10, 20, 30}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ac, err := NewUnanimityAccessStructure(hashset.NewComparable(tc.ids...).Freeze())
			require.NoError(t, err)

			m, err := InducedMSP(field, ac)
			require.NoError(t, err)

			// Only the full set should be accepted.
			require.True(t, m.Accepts(tc.ids...), "MSP should accept the full shareholder set")

			// Every proper subset should be rejected.
			n := uint(len(tc.ids))
			for k := uint(1); k < n; k++ {
				for combo := range sliceutils.Combinations(tc.ids, k) {
					require.False(t, m.Accepts(combo...),
						"MSP should reject proper subset of size %d: %v", k, combo)
				}
			}
		})
	}
}

func TestInducedByUnanimity_ReconstructionVector(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	ids := []ID{1, 2, 3}
	ac, err := NewUnanimityAccessStructure(hashset.NewComparable(ids...).Freeze())
	require.NoError(t, err)

	m, err := InducedMSP(field, ac)
	require.NoError(t, err)

	t.Run("full set succeeds", func(t *testing.T) {
		t.Parallel()
		rv, err := m.ReconstructionVector(ids...)
		require.NoError(t, err)
		require.NotNil(t, rv)
	})

	t.Run("missing one shareholder fails", func(t *testing.T) {
		t.Parallel()
		_, err := m.ReconstructionVector(1, 2)
		require.Error(t, err)
	})
}

func TestInducedByUnanimity_Dimensions(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	ids := []ID{1, 2, 3, 4}
	ac, err := NewUnanimityAccessStructure(hashset.NewComparable(ids...).Freeze())
	require.NoError(t, err)

	m, err := InducedMSP(field, ac)
	require.NoError(t, err)

	// For unanimity with n shareholders, the CNF has n maximal unqualified sets,
	// each clause is a singleton, so MSP has n rows and n columns.
	require.Equal(t, uint(len(ids)), m.Size(), "MSP should have one row per shareholder")
	require.Equal(t, uint(len(ids)), m.D(), "MSP dimension should equal number of shareholders")
}

func canonicalIDs(s ds.Set[ID]) string {
	ids := s.List()
	slices.Sort(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprint(id))
	}
	return strings.Join(parts, ",")
}
