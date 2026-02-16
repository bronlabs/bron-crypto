package bitset_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

func TestBitSet_CBOR_MarshalUnmarshal(t *testing.T) {
	t.Parallel()

	t.Run("empty set", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)

		data, err := serde.MarshalCBOR(s)
		require.NoError(t, err)
		require.NotNil(t, data)

		recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data)
		require.NoError(t, err)

		require.Equal(t, 0, recovered.Size())
		require.True(t, s.Equal(&recovered))
	})

	t.Run("single element", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint64](5)

		data, err := serde.MarshalCBOR(*s)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data)
		require.NoError(t, err)

		require.Equal(t, 1, recovered.Size())
		require.True(t, recovered.Contains(5))
		require.True(t, s.Equal(&recovered))
	})

	t.Run("multiple elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint64](1, 5, 10, 32, 64)

		data, err := serde.MarshalCBOR(*s)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data)
		require.NoError(t, err)

		require.Equal(t, 5, recovered.Size())
		require.True(t, recovered.Contains(1))
		require.True(t, recovered.Contains(5))
		require.True(t, recovered.Contains(10))
		require.True(t, recovered.Contains(32))
		require.True(t, recovered.Contains(64))
		require.True(t, s.Equal(&recovered))
	})

	t.Run("all 64 elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		for i := uint64(1); i <= 64; i++ {
			s.Add(i)
		}

		data, err := serde.MarshalCBOR(s)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data)
		require.NoError(t, err)

		require.Equal(t, 64, recovered.Size())
		for i := uint64(1); i <= 64; i++ {
			require.True(t, recovered.Contains(i))
		}
		require.True(t, s.Equal(&recovered))
	})

	t.Run("boundary elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint64](1, 64)

		data, err := serde.MarshalCBOR(*s)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data)
		require.NoError(t, err)

		require.Equal(t, 2, recovered.Size())
		require.True(t, recovered.Contains(1))
		require.True(t, recovered.Contains(64))
		require.True(t, s.Equal(&recovered))
	})
}

func TestBitSet_CBOR_DifferentTypes(t *testing.T) {
	t.Parallel()

	t.Run("uint8", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint8](1, 2, 3, 10)

		data, err := serde.MarshalCBOR(*s)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint8]](data)
		require.NoError(t, err)

		require.Equal(t, 4, recovered.Size())
		require.True(t, s.Equal(&recovered))
	})

	t.Run("uint16", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint16](5, 15, 25, 35)

		data, err := serde.MarshalCBOR(*s)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint16]](data)
		require.NoError(t, err)

		require.Equal(t, 4, recovered.Size())
		require.True(t, s.Equal(&recovered))
	})

	t.Run("uint32", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint32](7, 14, 21, 28)

		data, err := serde.MarshalCBOR(*s)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint32]](data)
		require.NoError(t, err)

		require.Equal(t, 4, recovered.Size())
		require.True(t, s.Equal(&recovered))
	})
}

func TestImmutableBitSet_CBOR_MarshalUnmarshal(t *testing.T) {
	t.Parallel()

	t.Run("empty set", func(t *testing.T) {
		t.Parallel()
		s := bitset.ImmutableBitSet[uint64](0)

		data, err := serde.MarshalCBOR(s)
		require.NoError(t, err)
		require.NotNil(t, data)

		recovered, err := serde.UnmarshalCBOR[bitset.ImmutableBitSet[uint64]](data)
		require.NoError(t, err)

		require.Equal(t, 0, recovered.Size())
		require.True(t, s.Equal(recovered))
	})

	t.Run("multiple elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewImmutableBitSet[uint64](3, 7, 11, 13, 17)

		data, err := serde.MarshalCBOR(s)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.ImmutableBitSet[uint64]](data)
		require.NoError(t, err)

		require.Equal(t, 5, recovered.Size())
		require.True(t, recovered.Contains(3))
		require.True(t, recovered.Contains(7))
		require.True(t, recovered.Contains(11))
		require.True(t, recovered.Contains(13))
		require.True(t, recovered.Contains(17))
		require.True(t, s.Equal(recovered))
	})

	t.Run("frozen set preserves through serialisation", func(t *testing.T) {
		t.Parallel()
		mutable := bitset.NewBitSet[uint64](2, 4, 6, 8)
		frozen := mutable.Freeze()

		data, err := serde.MarshalCBOR(frozen)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.ImmutableBitSet[uint64]](data)
		require.NoError(t, err)

		require.Equal(t, 4, recovered.Size())
		require.True(t, frozen.Equal(recovered))
	})
}

func TestBitSet_CBOR_RoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("multiple round trips preserve data", func(t *testing.T) {
		t.Parallel()
		original := bitset.NewBitSet[uint64](1, 3, 5, 7, 9, 11)

		// First round trip
		data1, err := serde.MarshalCBOR(*original)
		require.NoError(t, err)

		recovered1, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data1)
		require.NoError(t, err)

		// Second round trip
		data2, err := serde.MarshalCBOR(recovered1)
		require.NoError(t, err)

		recovered2, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data2)
		require.NoError(t, err)

		// All should be equal
		require.True(t, original.Equal(&recovered1))
		require.True(t, original.Equal(&recovered2))
		require.True(t, recovered1.Equal(&recovered2))

		// Data should be identical
		require.Equal(t, data1, data2)
	})

	t.Run("mutable to immutable and back", func(t *testing.T) {
		t.Parallel()
		mutable := bitset.NewBitSet[uint64](10, 20, 30, 40, 50)

		// Marshal mutable
		data, err := serde.MarshalCBOR(*mutable)
		require.NoError(t, err)

		// Unmarshal as immutable
		immutable, err := serde.UnmarshalCBOR[bitset.ImmutableBitSet[uint64]](data)
		require.NoError(t, err)

		// Verify equality
		require.Equal(t, mutable.Size(), immutable.Size())
		for e := range mutable.Iter() {
			require.True(t, immutable.Contains(e))
		}

		// Marshal immutable
		data2, err := serde.MarshalCBOR(immutable)
		require.NoError(t, err)

		// Unmarshal back to mutable
		mutable2, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data2)
		require.NoError(t, err)

		require.True(t, mutable.Equal(&mutable2))
	})
}

func TestBitSet_CBOR_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("specific bit patterns", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			elements []uint64
		}{
			{"consecutive", []uint64{1, 2, 3, 4, 5}},
			{"powers of 2", []uint64{1, 2, 4, 8, 16, 32, 64}},
			{"every other", []uint64{2, 4, 6, 8, 10, 12}},
			{"sparse", []uint64{1, 17, 33, 49}},
			{"high values", []uint64{60, 61, 62, 63, 64}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				s := bitset.NewBitSet(tc.elements...)

				data, err := serde.MarshalCBOR(*s)
				require.NoError(t, err)

				recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data)
				require.NoError(t, err)

				require.Equal(t, len(tc.elements), recovered.Size())
				require.True(t, s.Equal(&recovered))
			})
		}
	})

	t.Run("maximal bitset (all bits set)", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](^uint64(0)) // All bits set

		data, err := serde.MarshalCBOR(s)
		require.NoError(t, err)

		recovered, err := serde.UnmarshalCBOR[bitset.BitSet[uint64]](data)
		require.NoError(t, err)

		require.Equal(t, 64, recovered.Size())
		require.Equal(t, uint64(s), uint64(recovered))
	})
}
