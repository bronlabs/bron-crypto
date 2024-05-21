package natplus

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/natplus/bigint"
)

type (
	NPlus   integer.NPlus[bigint.NPlus, bigint.NatPlus]
	NatPlus integer.NatPlus[bigint.NPlus, bigint.NatPlus]
)

func ToNatPlus[T any](n integer.Number[T]) NatPlus {

}
