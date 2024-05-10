package bigint

import "github.com/copperexchange/krypton-primitives/pkg/base/integer"

type NPlus struct {
	integer.NPlus[*NPlus, *NatPlus]
}
