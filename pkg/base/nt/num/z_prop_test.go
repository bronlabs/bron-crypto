package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"pgregory.net/rapid"
)

func IntGenerator(t *testing.T) *rapid.Generator[*num.Int] {
	return rapid.Custom(func(t *rapid.T) *num.Int {
		n := rapid.Int64().Draw(t, "n")
		return num.Z().FromInt64(n)
	})
}

func SmallIntGenerator(t *testing.T) *rapid.Generator[*num.Int] {
	return rapid.Custom(func(t *rapid.T) *num.Int {
		n := rapid.Int16().Draw(t, "n")
		return num.Z().FromInt64(int64(n))
	})
}
