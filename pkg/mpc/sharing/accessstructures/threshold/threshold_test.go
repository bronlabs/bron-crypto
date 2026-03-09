//nolint:testpackage // White-box tests validate internal access-structure state.
package threshold

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

func TestInducedMSPByThreshold_Errors(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	ac, err := NewThresholdAccessStructure(2, hashset.NewComparable[ID](1, 2, 3).Freeze())
	require.NoError(t, err)

	t.Run("nil field", func(t *testing.T) {
		t.Parallel()
		m, err := InducedMSPByThreshold[*k256.Scalar](nil, ac)
		require.ErrorIs(t, err, ErrIsNil)
		require.Nil(t, m)
	})

	t.Run("nil access structure", func(t *testing.T) {
		t.Parallel()
		m, err := InducedMSPByThreshold(field, nil)
		require.ErrorIs(t, err, ErrIsNil)
		require.Nil(t, m)
	})
}

func TestInducedMSPByThreshold_Dimensions(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	tests := []struct {
		name string
		t_   uint
		ids  []ID
	}{
		{name: "2-of-3", t_: 2, ids: []ID{1, 2, 3}},
		{name: "2-of-4", t_: 2, ids: []ID{1, 2, 3, 4}},
		{name: "3-of-5", t_: 3, ids: []ID{1, 2, 3, 4, 5}},
		{name: "4-of-4", t_: 4, ids: []ID{1, 2, 3, 4}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ac, err := NewThresholdAccessStructure(tc.t_, hashset.NewComparable(tc.ids...).Freeze())
			require.NoError(t, err)

			m, err := InducedMSPByThreshold(field, ac)
			require.NoError(t, err)

			n := len(tc.ids)
			require.Equal(t, uint(n), m.Size(), "MSP size (rows) should equal number of shareholders")
			require.Equal(t, uint(tc.t_), m.D(), "MSP dimension (cols) should equal threshold")

			rows, cols := m.Matrix().Dimensions()
			require.Equal(t, n, rows)
			require.Equal(t, int(tc.t_), cols)
		})
	}
}

func TestInducedMSPByThreshold_RowMapping(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	ids := []ID{1, 2, 3, 4}
	ac, err := NewThresholdAccessStructure(3, hashset.NewComparable(ids...).Freeze())
	require.NoError(t, err)

	m, err := InducedMSPByThreshold(field, ac)
	require.NoError(t, err)

	rth := m.RowsToHolders()
	htr := m.HoldersToRows()

	// Each row maps to exactly one shareholder.
	require.Len(t, ids, rth.Size())
	for i := range ids {
		id, ok := rth.Get(i)
		require.True(t, ok, "row %d must have a holder mapping", i)
		require.Contains(t, ids, id)
	}

	// Each shareholder maps to exactly one row (threshold MSP is one-row-per-party).
	holderSet := hashset.NewComparable[ID]()
	for id, rows := range htr.Iter() {
		require.Equal(t, 1, rows.Size(), "shareholder %d should own exactly one row", id)
		holderSet.Add(id)
	}
	require.True(t, holderSet.Freeze().Equal(ac.Shareholders()))
}

func TestInducedMSPByThreshold_TargetVector(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	ac, err := NewThresholdAccessStructure(2, hashset.NewComparable[ID](1, 2, 3).Freeze())
	require.NoError(t, err)

	m, err := InducedMSPByThreshold(field, ac)
	require.NoError(t, err)

	tv := m.TargetVector()
	require.True(t, tv.IsRowVector())
	_, cols := tv.Dimensions()
	require.Equal(t, 2, cols, "target vector length should equal threshold")

	// Target should be e_0 = (1, 0, ..., 0).
	v0, err := tv.Get(0, 0)
	require.NoError(t, err)
	require.True(t, v0.IsOne(), "target[0] should be 1")
	for c := 1; c < cols; c++ {
		v, err := tv.Get(0, c)
		require.NoError(t, err)
		require.True(t, v.IsZero(), "target[%d] should be 0", c)
	}
}

func TestInducedMSPByThreshold_AcceptsQualifiedSets(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	tests := []struct {
		name string
		t_   uint
		ids  []ID
	}{
		{name: "2-of-3", t_: 2, ids: []ID{1, 2, 3}},
		{name: "3-of-4", t_: 3, ids: []ID{1, 2, 3, 4}},
		{name: "2-of-5", t_: 2, ids: []ID{1, 2, 3, 4, 5}},
		{name: "4-of-4", t_: 4, ids: []ID{1, 2, 3, 4}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ac, err := NewThresholdAccessStructure(tc.t_, hashset.NewComparable(tc.ids...).Freeze())
			require.NoError(t, err)
			m, err := InducedMSPByThreshold(field, ac)
			require.NoError(t, err)

			// Every subset of size >= t should be accepted.
			for k := tc.t_; k <= uint(len(tc.ids)); k++ {
				for combo := range sliceutils.Combinations(tc.ids, k) {
					require.True(t, m.Accepts(combo...),
						"MSP should accept qualified set of size %d: %v", k, combo)
				}
			}
		})
	}
}

func TestInducedMSPByThreshold_RejectsUnqualifiedSets(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	tests := []struct {
		name string
		t_   uint
		ids  []ID
	}{
		{name: "2-of-3", t_: 2, ids: []ID{1, 2, 3}},
		{name: "3-of-4", t_: 3, ids: []ID{1, 2, 3, 4}},
		{name: "2-of-5", t_: 2, ids: []ID{1, 2, 3, 4, 5}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ac, err := NewThresholdAccessStructure(tc.t_, hashset.NewComparable(tc.ids...).Freeze())
			require.NoError(t, err)
			m, err := InducedMSPByThreshold(field, ac)
			require.NoError(t, err)

			// Every subset of size < t should be rejected.
			for k := uint(1); k < tc.t_; k++ {
				for combo := range sliceutils.Combinations(tc.ids, k) {
					require.False(t, m.Accepts(combo...),
						"MSP should reject unqualified set of size %d: %v", k, combo)
				}
			}
		})
	}
}

func TestInducedMSPByThreshold_ReconstructionVector(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	ids := []ID{1, 2, 3, 4}
	ac, err := NewThresholdAccessStructure(3, hashset.NewComparable(ids...).Freeze())
	require.NoError(t, err)
	m, err := InducedMSPByThreshold(field, ac)
	require.NoError(t, err)

	t.Run("qualified set succeeds", func(t *testing.T) {
		t.Parallel()
		recVec, err := m.ReconstructionVector(1, 2, 3)
		require.NoError(t, err)
		require.NotNil(t, recVec)

		// SolveLeft returns a k×1 column vector of reconstruction coefficients.
		rows, cols := recVec.Dimensions()
		require.Equal(t, 3, rows, "reconstruction vector should have one coefficient per selected row")
		require.Equal(t, 1, cols)
	})

	t.Run("all shareholders succeeds", func(t *testing.T) {
		t.Parallel()
		recVec, err := m.ReconstructionVector(1, 2, 3, 4)
		require.NoError(t, err)
		require.NotNil(t, recVec)

		rows, cols := recVec.Dimensions()
		require.Equal(t, 4, rows)
		require.Equal(t, 1, cols)
	})

	t.Run("unqualified set fails", func(t *testing.T) {
		t.Parallel()
		_, err := m.ReconstructionVector(1, 2)
		require.Error(t, err, "reconstruction should fail for unqualified set")
	})
}

func TestInducedMSPByThreshold_LargerIDs(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	ids := []ID{10, 20, 30, 40, 50}
	ac, err := NewThresholdAccessStructure(3, hashset.NewComparable(ids...).Freeze())
	require.NoError(t, err)

	m, err := InducedMSPByThreshold(field, ac)
	require.NoError(t, err)

	// Spot-check: all 3-subsets accepted, all 2-subsets rejected.
	for combo := range sliceutils.Combinations(ids, 3) {
		require.True(t, m.Accepts(combo...), "should accept qualified set %v", combo)
	}
	for combo := range sliceutils.Combinations(ids, 2) {
		require.False(t, m.Accepts(combo...), "should reject unqualified set %v", combo)
	}
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
