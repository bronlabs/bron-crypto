package bimap_test

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bimap"
)

var (
	_ ds.BiMap[string, int]        = (*bimap.ImmutableBiMap[string, int])(nil)
	_ ds.MutableBiMap[string, int] = (*bimap.MutableBiMap[string, int])(nil)
	_ ds.ConcurrentBiMap[any, any] = (*bimap.ConcurrentBiMap[any, any])(nil)
)
