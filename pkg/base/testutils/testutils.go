package testutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"pgregory.net/rapid"
)

func UintsGenerator(minLen, maxLen int, distinct bool) *rapid.Generator[[]uint] {
	if maxLen < 1 || minLen < 1 || maxLen < maxLen {
		panic(errs.NewFailed("maxLen (%d) & minLen (%d) ", maxLen, minLen))
	}

	if distinct {
		return rapid.SliceOfNDistinct(rapid.Uint(), minLen, maxLen, rapid.ID)
	}
	return rapid.SliceOfN(rapid.Uint(), minLen, maxLen)
}
