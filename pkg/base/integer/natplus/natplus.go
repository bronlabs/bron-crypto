package natplus

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	bigImpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/natplus/bigint"
	"github.com/cronokirby/saferith"
)

type (
	NPlus   integer.NPlus[*bigImpl.NPlus, *bigImpl.NatPlus]
	NatPlus integer.NatPlus[*bigImpl.NPlus, *bigImpl.NatPlus]
)

func New[T impl.NatPlusValue](v T) (NatPlus, error) {
	switch vv := any(v).(type) {
	case *saferith.Nat:
		if vv == nil {
			return nil, errs.NewIsNil("argument")
		}
		if vv.EqZero() == 1 {
			return nil, errs.NewIsZero("argument")
		}
		return new(bigImpl.NatPlus).SetNat(vv), nil
	case *saferith.Modulus:
		if vv == nil {
			return nil, errs.NewIsNil("argument")
		}
		return new(bigImpl.NatPlus).SetNat(vv.Nat()), nil
	case uint64:
		if vv == 0 {
			return nil, errs.NewIsZero("argument")
		}
		return bigImpl.NewNatPlus(vv), nil
	default:
		return nil, errs.NewType("unsupported type %v", vv)
	}
}
