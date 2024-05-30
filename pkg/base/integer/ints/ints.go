package ints

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	bigImpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/ints/bigint"
	"github.com/cronokirby/saferith"
)

type (
	Z   integer.Z[*bigImpl.Z, *bigImpl.Int]
	Int integer.Int[*bigImpl.Z, *bigImpl.Int]
)

func New[T impl.IntValue](v T) (Int, error) {
	switch vv := any(v).(type) {
	case *saferith.Int:
		if vv == nil {
			return nil, errs.NewIsNil("argument")
		}
		return new(bigImpl.Int).SetInt(vv), nil
	case *big.Int:
		if vv == nil {
			return nil, errs.NewIsNil("argument")
		}
		return new(bigImpl.Int).SetBig(vv), nil
	case int64:
		return bigImpl.NewInt(vv), nil
	default:
		return nil, errs.NewType("unsupported type %v", vv)
	}
}
