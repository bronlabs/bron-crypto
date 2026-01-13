package hashmap_test

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

var (
	_ ds.Map[string, int]        = (*hashmap.ImmutableComparableMap[string, int])(nil)
	_ ds.MutableMap[string, int] = (*hashmap.MutableComparableMap[string, int])(nil)

	_ ds.Map[*HashableKey, int]        = (*hashmap.ImmutableHashableMap[*HashableKey, int])(nil)
	_ ds.MutableMap[*HashableKey, int] = (*hashmap.MutableHashableMap[*HashableKey, int])(nil)

	_ ds.ConcurrentMap[any, any] = (*hashmap.ConcurrentMap[any, any])(nil)
)
