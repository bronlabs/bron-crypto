package nat

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	bigImpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/nat/bigint"
	"github.com/cronokirby/saferith"
)

type (
	N   = integer.N[*bigImpl.N, *bigImpl.Nat]
	Nat = integer.Nat[*bigImpl.N, *bigImpl.Nat]
)

func New[T impl.NatValue](v T) (Nat, error) {
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
