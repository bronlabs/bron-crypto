package testutils

import "testing"

// Number of new inputs against which we run the tests. Eg. we say a structure is commutative if we apply the operation enough times and see it commute
// without an error.
const propertyCheckLimit = 100

type IsElement[S, E any] func(t *testing.T, s S, e E)
type IsStructure[S, E any] func(t *testing.T, s S)
