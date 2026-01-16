package hashset_test

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

var (
	_ ds.MutableSet[string]           = (*hashset.MutableComparableSet[string])(nil)
	_ ds.MutableSet[*HashableElement] = (*hashset.MutableHashableSet[*HashableElement])(nil)

	_ ds.Set[string]           = (*hashset.ImmutableSet[string])(nil)
	_ ds.Set[*HashableElement] = (*hashset.ImmutableSet[*HashableElement])(nil)

	_ ds.ConcurrentSet[any] = (*hashset.ConcurrentSet[any])(nil)
)
