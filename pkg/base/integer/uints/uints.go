package uints

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/nat"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/natplus"
	bigImpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/uints/bigint"
	"github.com/cronokirby/saferith"
)

type (
	Zn   = integer.Zn[bigImpl.Zn, bigImpl.Uint]
	Uint = integer.Uint[bigImpl.Zn, bigImpl.Uint]
)

func New(value nat.Nat, modulus natplus.NatPlus) (Uint, error) {
	switch vv := any(v).(type) {
	case *saferith.Nat:
		if vv == nil {
			return nil, errs.NewIsNil("argument")
		}
		return new(bigImpl.Nat).SetNat(vv), nil
	case uint64:
		return bigImpl.NewNat(vv), nil
	default:
		return nil, errs.NewType("unsupported type %v", vv)
	}
}
