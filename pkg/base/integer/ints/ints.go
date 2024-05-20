package ints

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/ints/bigint"
)

type (
	Z   integer.Z[*bigint.Z, *bigint.Int]
	Int integer.Int[*bigint.Z, *bigint.Int]
)

func NewInt(v uint64) Int {
	return bigint.NewInt(v)
}
