package bitset_test

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
)

var (
	_ ds.MutableSet[uint64] = (*bitset.BitSet[uint64])(nil)
	_ ds.Set[uint64]        = (bitset.ImmutableBitSet[uint64])(0)
	_ ds.MutableSet[uint32] = (*bitset.BitSet[uint32])(nil)
	_ ds.Set[uint16]        = (bitset.ImmutableBitSet[uint16])(0)
)
